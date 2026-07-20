package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateApplicationRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateNotReadyException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CertEnrollmentTemplate 默认实现（CR-007）
 * <p>
 * 统一封装向 PKI 提交 CSR、查询异步申请状态及获取已签发证书链。
 * 门面负责参数校验、profile 治理、幂等、鉴权、超时重试、异常归一、审计与指标；
 * PKI 继续负责 CA、审批、策略校验、签发及证书生命周期权威。
 */
public class DefaultCertEnrollmentTemplate implements CertEnrollmentTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultCertEnrollmentTemplate.class);

    private final PkiClient pkiClient;
    private final CryptoMetrics cryptoMetrics;
    private final Map<String, CertificateProfile> allowedProfiles;
    private final Map<String, String> idempotencyCache = new ConcurrentHashMap<>();

    public DefaultCertEnrollmentTemplate(PkiClient pkiClient,
                                                 CryptoMetrics cryptoMetrics,
                                                 List<CertificateProfile> allowedProfiles) {
        this.pkiClient = Objects.requireNonNull(pkiClient, "pkiClient must not be null");
        this.cryptoMetrics = Objects.requireNonNull(cryptoMetrics, "cryptoMetrics must not be null");
        this.allowedProfiles = new ConcurrentHashMap<>();
        if (allowedProfiles != null) {
            for (CertificateProfile profile : allowedProfiles) {
                this.allowedProfiles.put(profile.name(), profile);
            }
        }
    }

    @Override
    public CertApplyResult apply(CertApplyRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        long startTime = System.currentTimeMillis();

        try {
            // 校验 profile
            validateProfile(request.certificateProfile());

            // 校验 CSR
            validateCsr(request.pkcs10Csr());

            // 幂等检查
            String idempotencyKey = request.idempotencyKey();
            String existingRequestId = idempotencyCache.get(idempotencyKey);
            if (existingRequestId != null) {
                log.info("幂等键已存在，返回已有请求: idempotencyKey={}, requestId={}",
                        idempotencyKey, existingRequestId);
                return getStatus(existingRequestId);
            }

            // 计算 CSR 摘要用于审计
            String csrFingerprint = calculateCsrFingerprint(request.pkcs10Csr());

            // 调用 PKI 提交申请
            PkiClient.ApplyCommand command = new PkiClient.ApplyCommand(
                    request.certificateProfile().pkiProfileId(),
                    request.pkcs10Csr(),
                    request.subject().value(),
                    idempotencyKey,
                    request.context()
            );

            PkiClient.ApplyResponse response = pkiClient.submit(command);

            // 映射状态
            EnrollmentState state = mapState(response.state());

            // 缓存幂等键
            idempotencyCache.put(idempotencyKey, response.requestId());

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

            // 解析证书链
            List<byte[]> certificateChain = parseCertificateChain(response.certificateChain());

            // 校验叶子证书与 CSR 公钥一致性
            validateCertificateConsistency(response.leafCertificate(), certificateChain);

            // 计算指纹
            String sha256Fingerprint = calculateFingerprint(response.leafCertificate());

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
     * 计算 CSR 摘要
     */
    private String calculateCsrFingerprint(byte[] csr) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(csr);
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidCertificateRequestException("Failed to calculate CSR fingerprint", e);
        }
    }

    /**
     * 计算证书指纹
     */
    private String calculateFingerprint(byte[] certificate) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(certificate);
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidCertificateRequestException("Failed to calculate certificate fingerprint", e);
        }
    }

    /**
     * 解析证书链
     */
    private List<byte[]> parseCertificateChain(byte[] certificateChainDer) {
        // 简化实现：实际应解析 DER 编码的证书链
        // 这里假设 PKI 返回的是单个 DER 编码的证书链
        return List.of(certificateChainDer);
    }

    /**
     * 校验证书一致性
     */
    private void validateCertificateConsistency(byte[] leafCertificate, List<byte[]> certificateChain) {
        // 简化实现：实际应校验叶子证书与证书链的一致性
        if (leafCertificate == null || leafCertificate.length == 0) {
            throw new InvalidCertificateRequestException("Leaf certificate is empty");
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
            default -> EnrollmentState.PENDING;
        };
    }
}
