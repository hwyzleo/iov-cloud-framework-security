package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateChainValidator;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.EnrollmentIdempotencyService;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.EnrollmentRecord;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.InMemoryCertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.UuidV7;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateNotReadyException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CertEnrollmentTemplate 默认实现（CR-007 + FW-SEC-DSN-CR-008）
 * <p>
 * 统一封装向 PKI 提交 CSR、查询申请状态及获取已签发证书链。
 * 门面负责参数校验、profile 治理、幂等、鉴权、超时重试、异常归一、审计与指标；
 * PKI 继续负责 CA、审批、策略校验、签发及证书生命周期权威。
 * <p>
 * FW-SEC-DSN-CR-008：幂等与 CSR 留存迁移至持久化 {@link CertificateEnrollmentResultStore}；
 * step-ca 提供方自行管理结果存储（{@code PkiClient#managesResultStore()}），legacy-rest 由本门面在
 * submit 后回写；证书链一致性校验收敛至 {@link CertificateChainValidator}。
 */
public class DefaultCertEnrollmentTemplate implements CertEnrollmentTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultCertEnrollmentTemplate.class);
    private static final String DEFAULT_CALLER = "default";

    private final PkiClient pkiClient;
    private final CryptoMetrics cryptoMetrics;
    private final Map<String, CertificateProfile> allowedProfiles;
    private final CertificateEnrollmentResultStore resultStore;
    private final EnrollmentIdempotencyService idempotencyService;
    private final CertificateChainValidator chainValidator;

    public DefaultCertEnrollmentTemplate(PkiClient pkiClient,
                                         CryptoMetrics cryptoMetrics,
                                         List<CertificateProfile> allowedProfiles,
                                         CertificateEnrollmentResultStore resultStore,
                                         EnrollmentIdempotencyService idempotencyService,
                                         CertificateChainValidator chainValidator) {
        this.pkiClient = Objects.requireNonNull(pkiClient, "pkiClient must not be null");
        this.cryptoMetrics = Objects.requireNonNull(cryptoMetrics, "cryptoMetrics must not be null");
        this.allowedProfiles = new ConcurrentHashMap<>();
        if (allowedProfiles != null) {
            for (CertificateProfile profile : allowedProfiles) {
                this.allowedProfiles.put(profile.name(), profile);
            }
        }
        this.resultStore = Objects.requireNonNull(resultStore, "resultStore must not be null");
        this.idempotencyService = Objects.requireNonNull(idempotencyService, "idempotencyService must not be null");
        this.chainValidator = Objects.requireNonNull(chainValidator, "chainValidator must not be null");
    }

    /**
     * 兼容构造（测试/存量调用）：使用进程内结果存储（仅开发/测试语义）。
     */
    public DefaultCertEnrollmentTemplate(PkiClient pkiClient,
                                         CryptoMetrics cryptoMetrics,
                                         List<CertificateProfile> allowedProfiles) {
        this(pkiClient, cryptoMetrics, allowedProfiles,
                new InMemoryCertificateEnrollmentResultStore(Duration.ofDays(30), 1000),
                new CertificateChainValidator());
    }

    private DefaultCertEnrollmentTemplate(PkiClient pkiClient,
                                          CryptoMetrics cryptoMetrics,
                                          List<CertificateProfile> allowedProfiles,
                                          CertificateEnrollmentResultStore resultStore,
                                          CertificateChainValidator chainValidator) {
        this(pkiClient, cryptoMetrics, allowedProfiles, resultStore,
                new EnrollmentIdempotencyService(resultStore), chainValidator);
    }

    @Override
    public CertApplyResult apply(CertApplyRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        long startTime = System.currentTimeMillis();
        String caller = request.context() != null
                ? request.context().getOrDefault("caller", DEFAULT_CALLER)
                : DEFAULT_CALLER;

        try {
            // 校验 profile / CSR
            validateProfile(request.certificateProfile());
            validateCsr(request.pkcs10Csr());

            String idempotencyKey = request.idempotencyKey();
            String csrFingerprint = EnrollmentRecord.sha256Hex(request.pkcs10Csr());

            // 幂等：同 key 同参返回原结果；同 key 异参抛冲突；UNKNOWN 不重签；FAILED/REJECTED 可重签
            Optional<EnrollmentRecord> existing = idempotencyService.findExisting(
                    caller, idempotencyKey, request.pkcs10Csr(), request.certificateProfile().name());
            if (existing.isPresent()) {
                EnrollmentRecord record = existing.get();
                log.info("幂等键已存在: idempotencyKey={}, requestId={}, state={}",
                        idempotencyKey, record.requestId(), record.state());
                if (EnrollmentIdempotencyService.isUnknownOutcome(record)) {
                    // 请求已发送但结果未知：不自动重新签发（FW-SEC-DSN-CR-008 §6）
                    cryptoMetrics.recordEnrollmentOutcome(provider(), "unknown");
                    return new CertApplyResult(record.requestId(), EnrollmentState.UNKNOWN, record.updatedAt());
                }
                if (EnrollmentIdempotencyService.isRetryableTerminal(record)) {
                    // 失败可重试：FAILED/REJECTED 未产生证书，允许以同 key 重新申请
                    log.info("幂等终态可重试，允许重新签发: requestId={}, state={}",
                            record.requestId(), record.state());
                } else {
                    // ISSUED/进行中：幂等返回既有结果，不重复提交
                    return getStatus(record.requestId());
                }
            }

            // framework 生成稳定 requestId（UUIDv7）
            String requestId = UuidV7.toString(UuidV7.random());

            PkiClient.ApplyCommand command = new PkiClient.ApplyCommand(
                    requestId,
                    request.certificateProfile().pkiProfileId(),
                    request.certificateProfile().name(),
                    request.pkcs10Csr(),
                    request.subject().value(),
                    idempotencyKey,
                    request.context() != null ? request.context() : Map.of()
            );

            PkiClient.ApplyResponse response = pkiClient.submit(command);

            // legacy-rest：submit 后回写结果存储（CSR 留存供 getCertificate 公钥一致性校验）
            if (!pkiClient.managesResultStore()) {
                EnrollmentState state = mapState(response.state());
                resultStore.save(new EnrollmentRecord(
                        response.requestId(), caller, idempotencyKey, request.pkcs10Csr(),
                        csrFingerprint, request.certificateProfile().name(), state,
                        null, null, null, null, null, null, null,
                        Instant.now(), Instant.now()));
                cryptoMetrics.recordEnrollmentOutcome(provider(), outcomeOf(state));
            }

            EnrollmentState state = mapState(response.state());
            cryptoMetrics.recordEnrollmentSubmit(provider());

            long duration = System.currentTimeMillis() - startTime;
            log.info("证书申请提交成功: requestId={}, profile={}, subject={}, csrFingerprint={}, state={}, duration={}ms",
                    response.requestId(), request.certificateProfile().name(),
                    request.subject().value(), csrFingerprint, state, duration);
            cryptoMetrics.recordCertificateEnrollment(duration);

            return new CertApplyResult(response.requestId(), state, Instant.now());

        } catch (Exception e) {
            cryptoMetrics.recordError();
            long duration = System.currentTimeMillis() - startTime;
            log.error("证书申请提交失败: profile={}, subject={}, duration={}ms",
                    request.certificateProfile().name(), request.subject().value(), duration, e);
            throw e;
        }
    }

    @Override
    public CertApplyResult getStatus(String requestId) {
        Objects.requireNonNull(requestId, "requestId must not be null");
        long startTime = System.currentTimeMillis();

        try {
            PkiClient.StatusResponse response = pkiClient.getStatus(requestId);
            EnrollmentState state = mapState(response.state());

            long duration = System.currentTimeMillis() - startTime;
            log.info("查询申请状态成功: requestId={}, state={}, duration={}ms",
                    requestId, state, duration);
            cryptoMetrics.recordCertificateEnrollmentQuery(duration);

            return new CertApplyResult(requestId, state, Instant.now());

        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("查询申请状态失败: requestId={}", requestId, e);
            throw e;
        }
    }

    @Override
    public IssuedCertificate getCertificate(String requestId) {
        Objects.requireNonNull(requestId, "requestId must not be null");
        long startTime = System.currentTimeMillis();

        try {
            // 先查询状态
            CertApplyResult statusResult = getStatus(requestId);
            if (statusResult.state() != EnrollmentState.ISSUED) {
                throw new CertificateNotReadyException(
                        "Certificate not ready for requestId=" + requestId + ", current state=" + statusResult.state());
            }

            // 获取证书
            PkiClient.CertificateResponse response = pkiClient.getCertificate(requestId);

            // 申请时提交的 CSR（供公钥一致性校验；缺失时 fail-closed）
            byte[] csr = resultStore.findByRequestId(requestId)
                    .map(EnrollmentRecord::csr)
                    .orElse(null);

            // 解析证书链（DER 分段，按出现顺序）
            List<byte[]> certificateChain = chainValidator.parseCertificateChain(response.certificateChain());

            // 校验叶子证书、证书链顺序与 CSR 公钥一致性
            chainValidator.validateCertificateConsistency(response.leafCertificate(), certificateChain, csr);

            // 计算指纹
            String sha256Fingerprint = chainValidator.calculateFingerprint(response.leafCertificate());

            IssuedCertificate issuedCertificate = new IssuedCertificate(
                    response.leafCertificate(),
                    certificateChain,
                    response.serialNumber(),
                    Instant.parse(response.notBefore()),
                    Instant.parse(response.notAfter()),
                    sha256Fingerprint
            );

            long duration = System.currentTimeMillis() - startTime;
            log.info("获取证书成功: requestId={}, serialNumber={}, fingerprint={}, duration={}ms",
                    requestId, response.serialNumber(), sha256Fingerprint, duration);
            cryptoMetrics.recordCertificateEnrollmentQuery(duration);

            return issuedCertificate;

        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("获取证书失败: requestId={}", requestId, e);
            throw e;
        }
    }

    /**
     * 校验证书配置文件是否允许
     */
    private void validateProfile(CertificateProfile profile) {
        if (!allowedProfiles.containsKey(profile.name())) {
            throw new CertificateProfileNotAllowedException(
                    "Certificate profile not allowed: " + profile.name());
        }
    }

    /**
     * 校验 CSR 格式
     */
    private void validateCsr(byte[] csr) {
        if (csr == null || csr.length == 0) {
            throw new InvalidCertificateRequestException("CSR must not be null or empty");
        }
        // 基础格式校验：检查是否为 PEM 或 DER 编码
        String csrStr = new String(csr, StandardCharsets.UTF_8).trim();
        boolean isPem = csrStr.contains("-----BEGIN CERTIFICATE REQUEST-----");
        boolean isDer = csr.length > 10 && csr[0] == 0x30; // DER SEQUENCE tag

        if (!isPem && !isDer) {
            throw new InvalidCertificateRequestException(
                    "CSR must be in PEM or DER format");
        }
    }

    /**
     * 映射 PKI 状态到 EnrollmentState
     */
    private EnrollmentState mapState(String pkiState) {
        if (pkiState == null) {
            return EnrollmentState.PENDING;
        }
        return switch (pkiState.toUpperCase()) {
            case "PENDING", "SUBMITTED" -> EnrollmentState.PENDING;
            case "APPROVING", "APPROVAL_PENDING" -> EnrollmentState.APPROVING;
            case "PROCESSING", "IN_PROGRESS" -> EnrollmentState.PROCESSING;
            case "ISSUED", "COMPLETED", "SUCCESS" -> EnrollmentState.ISSUED;
            case "REJECTED", "DENIED" -> EnrollmentState.REJECTED;
            case "FAILED", "ERROR" -> EnrollmentState.FAILED;
            case "UNKNOWN" -> EnrollmentState.UNKNOWN;
            default -> EnrollmentState.PENDING;
        };
    }

    private String provider() {
        return pkiClient.managesResultStore() ? "step-ca" : "legacy-rest";
    }

    private static String outcomeOf(EnrollmentState state) {
        return switch (state) {
            case ISSUED -> "issued";
            case REJECTED -> "rejected";
            case FAILED -> "failed";
            case UNKNOWN -> "unknown";
            default -> "pending";
        };
    }
}
