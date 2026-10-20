package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EcdsaP1363;
import net.hwyz.iov.cloud.framework.security.crypto.codec.ImportProofCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectReason;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.ImportProofRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceCertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.ValidatedTboxDeviceCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofAlgorithm;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofRejectReason;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofVerificationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.VerifiedImportProof;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * ImportProofVerifier 默认实现（FW-SEC-DSN-CR-016 §3/§4/§5/§6/§7）。
 * <p>
 * 固定验证流水线：
 * <ol>
 *   <li>校验请求非空、算法 allowlist、字段长度、版本范围与业务域 allowlist；</li>
 *   <li>由 framework 依据结构化字段调用 {@link ImportProofCanonical#proofInputV1} 构建唯一 canonical 输入；</li>
 *   <li>解析设备证书并统一校验链、时间、状态、Profile/EKU/KU 与 P-256；</li>
 *   <li>常量时间比较证书策略摘要；</li>
 *   <li>解析 P1363 r/s 并校验范围与 low-S；</li>
 *   <li>执行 ECDSA-SHA256 验签；</li>
 *   <li>返回最小非敏感验证结果。</li>
 * </ol>
 * <p>
 * 验签无副作用、无 outcome-unknown 语义；确定性拒绝与证书材料暂不可用分开分类。
 * 日志、异常与结果<strong>不</strong>输出 proof、proofInput、证书 DER、r/s 或完整摘要。
 */
public class DefaultImportProofVerifier implements ImportProofVerifier {

    private static final Logger log = LoggerFactory.getLogger(DefaultImportProofVerifier.class);

    private static final long MAX_BUSINESS_KEY_VERSION = Long.MAX_VALUE;

    private final CertResolver certResolver;
    private final CertificateEvidenceValidator evidenceValidator;
    private final CryptoProperties properties;
    private final CryptoMetrics cryptoMetrics;
    private final Clock clock;
    private final TboxDeviceCertificateValidator tboxCertificateValidator;

    public DefaultImportProofVerifier(CertResolver certResolver,
                                      CertificateEvidenceValidator evidenceValidator,
                                      CryptoProperties properties,
                                      CryptoMetrics cryptoMetrics,
                                      Clock clock) {
        this(certResolver, evidenceValidator, properties, cryptoMetrics, clock, null);
    }

    public DefaultImportProofVerifier(CertResolver certResolver,
                                      CertificateEvidenceValidator evidenceValidator,
                                      CryptoProperties properties,
                                      CryptoMetrics cryptoMetrics,
                                      Clock clock,
                                      TboxDeviceCertificateValidator tboxCertificateValidator) {
        this.certResolver = Objects.requireNonNull(certResolver, "certResolver must not be null");
        this.evidenceValidator = evidenceValidator;
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.cryptoMetrics = cryptoMetrics;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.tboxCertificateValidator = tboxCertificateValidator;
    }

    @Override
    public VerifiedImportProof verify(ImportProofVerificationRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        long startTime = System.currentTimeMillis();
        try {
            byte[] importProof = request.importProof();
            byte[] expectedDigest = request.expectedCertificateDigest();
            byte[] envelopeDigest = request.envelopeDigest();
            byte[] keyCheckValue = request.keyCheckValue();

            // 1. 算法 / 长度 / 上下文 allowlist（确定性拒绝）
            if (request.proofAlgorithm() != ImportProofAlgorithm.ECDSA_P256_SHA256_P1363) {
                throw reject(ImportProofRejectReason.ALGORITHM_NOT_ALLOWED,
                        "unsupported import proof algorithm");
            }
            requireLength(importProof, ImportProofAlgorithm.SIGNATURE_LENGTH, "importProof");
            requireLength(expectedDigest, ImportProofAlgorithm.DIGEST_LENGTH, "expectedCertificateDigest");
            requireLength(envelopeDigest, ImportProofAlgorithm.DIGEST_LENGTH, "envelopeDigest");
            requireLength(keyCheckValue, ImportProofAlgorithm.KCV_LENGTH, "keyCheckValue");
            if (request.deviceCertificateRef() == null) {
                throw reject(ImportProofRejectReason.CONTEXT_INVALID, "deviceCertificateRef must not be null");
            }
            if (isBlank(request.requestId())) {
                throw reject(ImportProofRejectReason.CONTEXT_INVALID, "requestId must not be blank");
            }
            if (!ImportProofCanonical.isAllowedBusinessDomainV1(request.businessDomain())) {
                throw reject(ImportProofRejectReason.CONTEXT_INVALID, "businessDomain not allowed");
            }
            KeyPurpose purpose = request.purpose();
            if (purpose == null || purpose.canonicalValue() <= 0) {
                throw reject(ImportProofRejectReason.CONTEXT_INVALID, "purpose is not a canonical provision purpose");
            }
            if (isBlank(request.keyId())) {
                throw reject(ImportProofRejectReason.CONTEXT_INVALID, "keyId must not be blank");
            }
            long businessKeyVersion = request.businessKeyVersion();
            if (businessKeyVersion < 1 || businessKeyVersion > MAX_BUSINESS_KEY_VERSION) {
                throw reject(ImportProofRejectReason.CONTEXT_INVALID, "businessKeyVersion out of range");
            }

            // 2. canonical proofInput（唯一生产契约）
            byte[] proofInput = ImportProofCanonical.proofInputV1(request.requestId(),
                    request.businessDomain(), purpose, request.keyId(), businessKeyVersion,
                    envelopeDigest, keyCheckValue);

            // 3. 证书解析 + 统一 Profile 校验（CR-017 §8）：与 CR-014 共享同一
            //    DeviceCertificateRef、同一 leaf DER 摘要与 freshness 语义（RD-017-2）。
            ValidatedTboxDeviceCertificate validated = validateCertificate(request.deviceCertificateRef());

            // 4. 常量时间证书策略摘要绑定（leaf DER digest；wire 摘要语义不变）
            byte[] certificateDigest = bindingDigest(request.deviceCertificateRef(), validated);
            if (!CanonicalEncoding.constantTimeEquals(expectedDigest, certificateDigest)) {
                profileOrProofReject(expectedDigest, certificateDigest);
            }

            // 5/6. P1363 r/s 范围 + low-S 校验，并执行 ECDSA-SHA256 验签
            PublicKey publicKey = validated != null
                    ? validated.publicKey()
                    : parsePublicKey(resolveEvidence(request.deviceCertificateRef()).spki());
            if (!(publicKey instanceof ECPublicKey)) {
                throw new CertificateEvidenceRejectedException(
                        CertificateEvidenceRejectedException.Reason.UNSUPPORTED_RECIPIENT_KEY,
                        "import proof requires an EC P-256 device certificate public key");
            }
            if (!EcdsaP1363.verify(publicKey, proofInput, importProof)) {
                throw reject(ImportProofRejectReason.SIGNATURE_INVALID,
                        "import proof signature verification failed");
            }

            // 7. 最小非敏感结果
            Instant verifiedAt = clock.instant();
            if (cryptoMetrics != null) {
                cryptoMetrics.recordImportProofVerify(System.currentTimeMillis() - startTime);
            }
            return new VerifiedImportProof(request.proofAlgorithm(), certificateDigest, purpose,
                    CanonicalEncoding.sha256(proofInput), verifiedAt);
        } catch (ImportProofRejectedException | CertificateEvidenceRejectedException
                 | CertificateProfileRejectedException e) {
            if (cryptoMetrics != null) {
                cryptoMetrics.recordImportProofRejection(rejectReasonOf(e));
            }
            log.warn("导入证明验签拒绝: reason={}", e.getReason());
            throw e;
        } catch (RuntimeException e) {
            if (cryptoMetrics != null) {
                cryptoMetrics.recordImportProofDependencyUnavailable();
            }
            log.error("导入证明验签失败（依赖/材料）: reason={}", reasonOf(e), e);
            throw e;
        }
    }

    private ValidatedTboxDeviceCertificate validateCertificate(DeviceCertificateRef ref) {
        if (tboxCertificateValidator != null) {
            return tboxCertificateValidator.validate(ref, DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1);
        }
        return null;
    }

    /**
     * 共享绑定摘要：Profile 装配时取统一验证结果的 leaf DER digest；否则回退既有
     * {@code SHA-256(certificateDer)}。wire 摘要语义不变（FW-SEC-DSN-CR-017 决策 1）。
     */
    private byte[] bindingDigest(DeviceCertificateRef ref, ValidatedTboxDeviceCertificate validated) {
        if (validated != null) {
            byte[] digest = validated.certificatePolicyDigest();
            if (digest != null) {
                return digest;
            }
        }
        CertificateEvidence evidence = resolveEvidence(ref);
        if (!evidence.hasLeafDer()) {
            throw new CryptoDependencyUnavailableException(
                    "import proof verification requires leaf certificate DER (bare SPKI not permitted)");
        }
        return CanonicalEncoding.sha256(evidence.certificateDer());
    }

    /**
     * 绑定不匹配拒绝：Profile 装配时以 CR-017 CERTIFICATE_BINDING_MISMATCH 分类（ECDSA Provider 调用前）；
     * 未装配 Profile 时保持既有 ImportProofRejectedException(CERTIFICATE_DIGEST_MISMATCH)。
     */
    private void profileOrProofReject(byte[] expectedDigest, byte[] actualDigest) {
        if (tboxCertificateValidator != null) {
            throw new CertificateProfileRejectedException(CertificateProfileRejectReason.CERTIFICATE_BINDING_MISMATCH,
                    "certificate binding mismatch: resolved certificate digest does not match expected digest");
        }
        throw reject(ImportProofRejectReason.CERTIFICATE_DIGEST_MISMATCH,
                "certificate policy digest does not match expected digest");
    }

    private CertificateEvidence resolveEvidence(DeviceCertificateRef ref) {
        CertificateResolvePolicy policy = policy();
        CertificateEvidence evidence = certResolver.resolve(ref, policy);
        if (evidenceValidator != null) {
            evidence = evidenceValidator.validate(evidence, ref, policy);
        }
        return evidence;
    }

    private CertificateResolvePolicy policy() {
        CryptoProperties.ImportProof.Certificate config = properties.getImportProof().getCertificate();
        Set<String> requiredEku = config.getRequiredEku() == null
                ? Set.of() : Set.copyOf(config.getRequiredEku());
        return CertificateResolvePolicy.importProofVerify(config.isRequireCertificate(),
                config.isRequireTrustedChain(), config.isRequireGoodStatus(), requiredEku);
    }

    private static PublicKey parsePublicKey(byte[] spki) {
        if (spki == null || spki.length == 0) {
            throw new CertificateMaterialUnavailableException(
                    "Resolved certificate evidence lacks public key SPKI");
        }
        try {
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
        } catch (Exception e) {
            throw new CertificateMaterialUnavailableException(
                    "Failed to parse device certificate public key SPKI", e);
        }
    }

    private static void requireLength(byte[] value, int expected, String field) {
        if (value == null || value.length != expected) {
            throw new ImportProofRejectedException(ImportProofRejectReason.INVALID_LENGTH,
                    field + " must be exactly " + expected + " bytes");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static ImportProofRejectedException reject(ImportProofRejectReason reason, String message) {
        return new ImportProofRejectedException(reason, message);
    }

    private static String rejectReasonOf(RuntimeException e) {
        if (e instanceof ImportProofRejectedException rejected && rejected.rejectReason() != null) {
            return rejected.rejectReason().name();
        }
        if (e instanceof CertificateProfileRejectedException profile && profile.rejectReason() != null) {
            return profile.rejectReason().name();
        }
        return e.getClass().getSimpleName();
    }

    private static String reasonOf(RuntimeException e) {
        if (e instanceof CryptoException crypto && crypto.getReason() != null) {
            return crypto.getReason().name();
        }
        return e.getClass().getSimpleName();
    }
}
