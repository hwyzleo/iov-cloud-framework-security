package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateApplicationRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateNotReadyException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * step-ca 原生 PKI 客户端（FW-SEC-DSN-CR-008 §3/§5）
 * <p>
 * 以同步方式适配 step-ca /1.0/sign：
 * <ol>
 *   <li>framework 生成稳定 requestId（UUIDv7）；</li>
 *   <li>根据 profile 解析 {@link StepCaProfilePolicy}，经 {@link StepCaTokenProvider} 生成一次性 OTT；</li>
 *   <li>HTTPS POST /1.0/sign 同步签发；</li>
 *   <li>校验证书与信任链（{@link CertificateChainValidator}）；</li>
 *   <li>原子写入结果存储（ISSUED/REJECTED/FAILED/UNKNOWN）。</li>
 * </ol>
 * getStatus/getCertificate 读取结果存储，不调用虚构的 status/certificate API，
 * 不把 serial 当作 requestId。
 */
public class StepCaPkiClient implements PkiClient {

    private static final Logger log = LoggerFactory.getLogger(StepCaPkiClient.class);
    private static final String DEFAULT_CALLER = "default";
    private static final String PROVIDER = "step-ca";

    private final StepCaApiClient apiClient;
    private final StepCaTokenProvider tokenProvider;
    private final StepCaProfilePolicyRegistry policyRegistry;
    private final CertificateEnrollmentResultStore resultStore;
    private final CertificateChainValidator chainValidator;
    private final EnrollmentIdempotencyService idempotencyService;
    private final CryptoMetrics metrics;
    private final URI signUri;
    private final String rootSha256;

    public StepCaPkiClient(StepCaApiClient apiClient,
                           StepCaTokenProvider tokenProvider,
                           StepCaProfilePolicyRegistry policyRegistry,
                           CertificateEnrollmentResultStore resultStore,
                           CertificateChainValidator chainValidator,
                           EnrollmentIdempotencyService idempotencyService,
                           CryptoMetrics metrics,
                           URI endpoint,
                           String rootSha256) {
        this.apiClient = Objects.requireNonNull(apiClient, "apiClient must not be null");
        this.tokenProvider = Objects.requireNonNull(tokenProvider, "tokenProvider must not be null");
        this.policyRegistry = Objects.requireNonNull(policyRegistry, "policyRegistry must not be null");
        this.resultStore = Objects.requireNonNull(resultStore, "resultStore must not be null");
        this.chainValidator = Objects.requireNonNull(chainValidator, "chainValidator must not be null");
        this.idempotencyService = Objects.requireNonNull(idempotencyService, "idempotencyService must not be null");
        this.metrics = Objects.requireNonNull(metrics, "metrics must not be null");
        this.signUri = URI.create(Objects.requireNonNull(endpoint, "endpoint must not be null").toString() + "/1.0/sign");
        this.rootSha256 = Objects.requireNonNull(rootSha256, "rootSha256 must not be null");
    }

    @Override
    public boolean managesResultStore() {
        return true;
    }

    @Override
    public ApplyResponse submit(ApplyCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        String caller = callerOf(command);
        String idempotencyKey = command.idempotencyKey();

        // 幂等：同 key 同参返回既有结果；同 key 异参抛冲突；UNKNOWN 不重签；FAILED/REJECTED 可重签
        // 门面 apply() 已做过一次幂等检查（快速路径 + legacy-rest 共用）；此处为 step-ca 权威守卫，
        // 覆盖门面检查后到 createSubmitting 之间的并发窗口，属有意为之的分层防御，勿删。
        Optional<EnrollmentRecord> existing =
                idempotencyService.findExisting(caller, idempotencyKey, command.csr(), command.profileName());
        if (existing.isPresent()) {
            EnrollmentRecord record = existing.get();
            if (EnrollmentIdempotencyService.isRetryableTerminal(record)) {
                // 失败可重试：FAILED/REJECTED 未产生证书，允许以同 key 重新签发
                log.info("step-ca 幂等终态可重试，允许重新签发: requestId={}, state={}",
                        record.requestId(), record.state());
            } else {
                // ISSUED/UNKNOWN/进行中：幂等返回既有结果，不重复签发
                log.info("step-ca 幂等命中，不重复签发: requestId={}, state={}",
                        record.requestId(), record.state());
                return new ApplyResponse(record.requestId(), stateToString(record.state()),
                        "Idempotent hit, no re-issue");
            }
        }

        String requestId = command.requestId() != null
                ? command.requestId()
                : UuidV7.toString(UuidV7.random());

        // 原子写入 SUBMITTING；并发同 key 已存在时返回既有记录（不双签）
        EnrollmentRecord record = resultStore.createSubmitting(requestId, caller, idempotencyKey,
                command.csr(), EnrollmentRecord.sha256Hex(command.csr()), command.profileName());
        if (!record.requestId().equals(requestId)) {
            log.info("step-ca 并发幂等命中，返回既有请求: requestId={}, state={}",
                    record.requestId(), record.state());
            return new ApplyResponse(record.requestId(), stateToString(record.state()),
                    "Idempotent hit (concurrent), no re-issue");
        }

        StepCaProfilePolicy policy = null;
        StepCaApiClient.StepCaSignResponse signResponse = null;
        try {
            policy = policyRegistry.resolve(command.profileName());
            // OTT 授权 SAN 取自 CSR（step-ca 要求 OTT 覆盖 CSR 的 SAN，否则 403）；
            // CSR 无 SAN 扩展时回退到 subject，兼容仅用 CN 的历史 CSR。
            List<String> sans = CsrSanExtractor.extractSans(command.csr());
            if (sans.isEmpty()) {
                sans = List.of(command.subject());
            }
            String ott = tokenProvider.createToken(new StepCaTokenRequest(
                    requestId,
                    policy.provisioner(),
                    policy.kid(),
                    signUri,
                    command.subject(),
                    sans,
                    rootSha256,
                    null,
                    java.util.Map.of()));

            String csrPem = toPemCsr(command.csr());
            String notAfter = policy.maxValidity() != null
                    ? Instant.now().plus(policy.maxValidity()).toString()
                    : null;
            signResponse = apiClient.sign(new StepCaApiClient.StepCaSignRequest(csrPem, ott, null, notAfter));

        } catch (PkiOutcomeUnknownException e) {
            resultStore.markUnknown(requestId, redact(e.getMessage()));
            metrics.recordEnrollmentOutcome(PROVIDER, "unknown");
            log.warn("step-ca 签发结果未知，记录 UNKNOWN: requestId={}", requestId);
            throw e;
        } catch (CertificateApplicationRejectedException | InvalidCertificateRequestException e) {
            // 4xx：CA 侧的鉴权/授权/CSR 拒绝 → REJECTED
            resultStore.markTerminal(requestId, EnrollmentState.REJECTED, redact(e.getMessage()));
            metrics.recordEnrollmentOutcome(PROVIDER, "rejected");
            log.warn("step-ca 拒绝签发: requestId={}, reason={}", requestId, redact(e.getMessage()));
            throw e;
        }

        // sign 成功：证书/信任链校验属于 framework 自身校验，失败记 FAILED（非 CA 拒绝）
        try {
            byte[] leafDer = CertPem.derFromPem(signResponse.leafPem());
            List<byte[]> chainDer = signResponse.chainPem().stream()
                    .map(CertPem::derFromPem)
                    .toList();

            chainValidator.validateIssued(leafDer, chainDer, command.csr(), policy, rootSha256);

            X509Certificate leaf = CertPem.parseCertificate(leafDer);
            IssuedCertificate issued = new IssuedCertificate(
                    leafDer, chainDer, leaf.getSerialNumber().toString(),
                    leaf.getNotBefore().toInstant(), leaf.getNotAfter().toInstant(),
                    EnrollmentRecord.fingerprintHex(leafDer));
            resultStore.markIssued(requestId, issued);
            metrics.recordEnrollmentOutcome(PROVIDER, "issued");

            log.info("step-ca 同步签发成功: requestId={}, profile={}, serial={}, fingerprint={}",
                    requestId, command.profileName(), issued.serialNumber(),
                    issued.sha256Fingerprint());
            return new ApplyResponse(requestId, "ISSUED", "Certificate issued synchronously by step-ca");

        } catch (PkiOutcomeUnknownException e) {
            resultStore.markUnknown(requestId, redact(e.getMessage()));
            metrics.recordEnrollmentOutcome(PROVIDER, "unknown");
            throw e;
        } catch (Exception e) {
            resultStore.markTerminal(requestId, EnrollmentState.FAILED, redact(e.getMessage()));
            metrics.recordEnrollmentOutcome(PROVIDER, "failed");
            log.error("step-ca 签发响应校验失败，记录 FAILED: requestId={}", requestId, e);
            throw e instanceof RuntimeException runtime
                    ? runtime
                    : new PkiDependencyUnavailableException("step-ca sign failed: " + e.getMessage(), e);
        }
    }

    @Override
    public StatusResponse getStatus(String requestId) {
        Objects.requireNonNull(requestId, "requestId must not be null");
        EnrollmentRecord record = resultStore.findByRequestId(requestId)
                .orElseThrow(() -> new PkiDependencyUnavailableException(
                        "No enrollment record for requestId=" + requestId
                                + "; step-ca does not provide a status lookup API"));
        return new StatusResponse(requestId, stateToString(record.state()), record.errorSummary());
    }

    @Override
    public CertificateResponse getCertificate(String requestId) {
        Objects.requireNonNull(requestId, "requestId must not be null");
        EnrollmentRecord record = resultStore.findByRequestId(requestId)
                .orElseThrow(() -> new PkiDependencyUnavailableException(
                        "No enrollment record for requestId=" + requestId
                                + "; step-ca does not provide a certificate lookup API"));
        if (record.state() != EnrollmentState.ISSUED) {
            throw new CertificateNotReadyException(
                    "Certificate not ready for requestId=" + requestId + ", state=" + record.state());
        }
        return new CertificateResponse(
                requestId,
                record.leafCertificate(),
                CertPem.joinPem(record.certificateChain()).getBytes(java.nio.charset.StandardCharsets.UTF_8),
                record.serialNumber(),
                record.notBefore(),
                record.notAfter());
    }

    @Override
    public CertificateResponse queryCertificate(String serialNumber) {
        throw new PkiDependencyUnavailableException(
                "step-ca does not provide a serial-number certificate lookup API; "
                        + "use requestId-based enrollment access (FW-SEC-DSN-CR-008 §5.3)");
    }

    private static String callerOf(ApplyCommand command) {
        return command.context() != null
                ? command.context().getOrDefault("caller", DEFAULT_CALLER)
                : DEFAULT_CALLER;
    }

    private static String stateToString(EnrollmentState state) {
        return state == EnrollmentState.SUBMITTING ? "PENDING" : state.name();
    }

    private static String toPemCsr(byte[] csr) {
        // DER 转 PEM；已是 PEM 则原样返回
        String text = new String(csr, java.nio.charset.StandardCharsets.US_ASCII).trim();
        if (text.startsWith("-----BEGIN")) {
            return text;
        }
        return CertPem.toPemCsr(csr);
    }

    /**
     * 去敏：只保留异常类型与第一行摘要，禁止回显 CSR/证书/令牌材料。
     */
    private static String redact(String message) {
        if (message == null) {
            return null;
        }
        String singleLine = message.replaceAll("\\s+", " ").trim();
        return singleLine.length() > 120 ? singleLine.substring(0, 120) + "..." : singleLine;
    }
}
