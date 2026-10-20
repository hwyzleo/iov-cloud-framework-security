package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectReason;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileVerificationUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceCertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.ValidatedTboxDeviceCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * 统一 TBOX 设备证书 Profile 验证器默认实现（FW-SEC-DSN-CR-017 §4/§5/§6）。
 * <p>
 * 固定校验流水线：
 * <ol>
 *   <li>Profile allowlist（仅 TBOX_DEVICE_ECDH_ES_P256_V1）；</li>
 *   <li>经 {@link CertResolver} 解析 + {@link CertificateEvidenceValidator} 统一校验
 *       （链 / 有效期 / 吊销状态，返回 {@code statusFreshUntil}）——<strong>不重复解析证书链</strong>；</li>
 *   <li>Profile 专属语义校验：CA=false、EC P-256、双 KU、clientAuth、关键扩展、身份绑定；</li>
 *   <li>leaf DER digest（SHA-256(leafCertificateDER)，沿用 wire 摘要语义，仅作内部绑定比较）；</li>
 *   <li>返回不可变 {@link ValidatedTboxDeviceCertificate}。</li>
 * </ol>
 * <p>
 * 分层边界（用户已确认）：链/有效期/吊销复用 {@link CertificateEvidenceValidator}；
 * 本类只负责 CA=false、P-256、digitalSignature+keyAgreement、clientAuth、身份/Profile、
 * 关键扩展与 leaf DER digest。单场景 KU 不在证据校验层收紧（RD-017-4）。
 * <p>
 * Profile 语义（RD-017-1）：EC NIST P-256、CA=false、KU=恰好 {digitalSignature, keyAgreement}、
 * EKU allowlist 仅 clientAuth（含 anyEKU/serverAuth/其他 → EKU_POLICY_CONFLICT）、
 * 无未知关键扩展、subject 携带设备身份。
 */
public class DefaultTboxDeviceCertificateValidator implements TboxDeviceCertificateValidator {

    private static final Logger log = LoggerFactory.getLogger(DefaultTboxDeviceCertificateValidator.class);

    // ==== X.509 OID（关键扩展 / EKU） ====
    private static final String OID_KEY_USAGE = "2.5.29.15";
    private static final String OID_BASIC_CONSTRAINTS = "2.5.29.19";
    private static final String OID_SUBJECT_ALT_NAME = "2.5.29.17";
    private static final String OID_EXTENDED_KEY_USAGE = "2.5.29.37";
    private static final String OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
    private static final String OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";

    /** 已知关键扩展 OID 集合（超出即 UNSUPPORTED_CRITICAL_EXTENSION）。 */
    private static final Set<String> KNOWN_CRITICAL_EXTENSIONS = Set.of(
            OID_KEY_USAGE, OID_BASIC_CONSTRAINTS, OID_SUBJECT_ALT_NAME,
            OID_EXTENDED_KEY_USAGE, OID_SUBJECT_KEY_IDENTIFIER, OID_AUTHORITY_KEY_IDENTIFIER);

    /** EKU allowlist v1：仅 clientAuth（FW-SEC-DSN-CR-017 决策）。 */
    private static final String OID_EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final String OID_EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    private static final String OID_EKU_ANY = "2.5.29.37.0";

    private final CertResolver certResolver;
    private final CertificateEvidenceValidator evidenceValidator;
    private final CryptoProperties properties;
    private final Clock clock;

    public DefaultTboxDeviceCertificateValidator(CertResolver certResolver,
                                                 CertificateEvidenceValidator evidenceValidator,
                                                 CryptoProperties properties,
                                                 Clock clock) {
        this.certResolver = Objects.requireNonNull(certResolver, "certResolver must not be null");
        this.evidenceValidator = evidenceValidator;
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * Profile 语义结果（供自检/诊断复用，不含链与状态）。
     *
     * @param p256           是否为 NIST P-256
     * @param digitalSignature KeyUsage 是否含 digitalSignature
     * @param keyAgreement    KeyUsage 是否含 keyAgreement
     * @param clientAuth      EKU 是否含 clientAuth（且无冲突）
     */
    public record ProfileSemantics(boolean p256, boolean digitalSignature, boolean keyAgreement,
                                   boolean clientAuth) {
    }

    /**
     * 单次解析 + 校验结果（包内复用，避免门面二次解析/二次链校验）。
     *
     * @param validated 已校验 Profile 证据
     * @param evidence  解析并统一校验后的规范化证据（链/状态已校验）
     */
    record ProfileValidation(ValidatedTboxDeviceCertificate validated, CertificateEvidence evidence) {
    }

    @Override
    public ValidatedTboxDeviceCertificate validate(DeviceCertificateRef ref, DeviceCertificateProfile profile) {
        return validateWithEvidence(ref, profile).validated();
    }

    /**
     * 单次解析 + 统一校验 + Profile 语义校验，同时返回规范化证据（FW-SEC-DSN-CR-017 §5）。
     * <p>
     * 门面（如 DefaultKeyProvisioningTemplate）复用本方法避免对同一证书二次解析/二次链校验。
     *
     * @param ref     证书引用
     * @param profile 目标 Profile
     * @return 已校验结果 + 规范化证据
     */
    ProfileValidation validateWithEvidence(DeviceCertificateRef ref, DeviceCertificateProfile profile) {
        Objects.requireNonNull(ref, "ref must not be null");
        Objects.requireNonNull(profile, "profile must not be null");
        if (profile != DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1) {
            throw new CertificateProfileRejectedException(CertificateProfileRejectReason.PROFILE_NOT_ALLOWED,
                    "Unsupported device certificate profile: " + profile);
        }

        // 1. 解析 + 统一证据校验（链 / 有效期 / 吊销状态 / 声明一致性）
        CertificateEvidence evidence = resolveEvidence(ref);
        if (!evidence.hasLeafDer()) {
            throw new CryptoDependencyUnavailableException(
                    "TBOX device certificate profile requires leaf certificate DER "
                            + "(bare SPKI not permitted, FW-SEC-DSN-CR-017 §5)");
        }
        if (evidenceValidator == null) {
            // 无证据校验器时不安全：fail-closed（不跳过链/状态校验）
            throw new CertificateProfileVerificationUnavailableException(
                    "CertificateEvidenceValidator is required for TBOX device certificate profile validation");
        }
        CertificateEvidenceValidator.ValidatedCertificate validatedEvidence =
                evidenceValidator.validateWithFreshness(evidence, ref, policy());

        // 2. Profile 专属语义校验（仅叶子，不解析链）
        X509Certificate leaf = CertificateEvidenceValidator.parseLeaf(evidence.certificateDer());
        ProfileSemantics semantics = evaluateProfile(leaf, profile);

        // 3. leaf DER digest（沿用 wire 摘要语义，仅内部绑定比较）
        byte[] digest = CanonicalEncoding.sha256(evidence.certificateDer());

        Instant statusFreshUntil = validatedEvidence == null ? null : validatedEvidence.statusFreshUntil();
        Instant validatedAt = clock.instant();
        log.info("TBOX 设备证书 Profile 校验通过: profile={}, p256={}, digitalSignature={}, keyAgreement={}, "
                        + "clientAuth={}, statusFreshUntil={}",
                profile, semantics.p256(), semantics.digitalSignature(), semantics.keyAgreement(),
                semantics.clientAuth(), statusFreshUntil);
        ValidatedTboxDeviceCertificate validated = new ValidatedTboxDeviceCertificate(
                profile, ref, leaf.getPublicKey(), digest,
                semantics.p256(), semantics.digitalSignature(), semantics.keyAgreement(),
                semantics.clientAuth(), validatedAt, statusFreshUntil);
        return new ProfileValidation(validated, validatedEvidence.evidence());
    }

    /**
     * Profile 专属语义校验（FW-SEC-DSN-CR-017 §5）。
     * <p>
     * 纯结构校验，<strong>不</strong>依赖链/时间/状态，供验证器主流程与 capability 自检复用。
     *
     * @param leaf    叶子证书
     * @param profile 目标 Profile
     * @return 语义位
     * @throws CertificateProfileRejectedException 任一 Profile 约束不满足（确定性、不可重试）
     */
    public static ProfileSemantics evaluateProfile(X509Certificate leaf, DeviceCertificateProfile profile) {
        Objects.requireNonNull(leaf, "leaf must not be null");
        if (profile != DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1) {
            throw profileReject(CertificateProfileRejectReason.PROFILE_NOT_ALLOWED,
                    "Unsupported device certificate profile: " + profile);
        }

        // CA=false（BasicConstraints 语义）：getBasicConstraints()==-1 表示非 CA
        if (leaf.getBasicConstraints() != -1) {
            throw profileReject(CertificateProfileRejectReason.NOT_END_ENTITY,
                    "Leaf certificate is a CA (BasicConstraints CA=true), profile requires CA=false");
        }

        // 公钥算法：EC
        if (!(leaf.getPublicKey() instanceof java.security.interfaces.ECPublicKey)) {
            throw profileReject(CertificateProfileRejectReason.PUBLIC_KEY_ALGORITHM_NOT_ALLOWED,
                    "Leaf public key is not EC: " + leaf.getPublicKey().getAlgorithm());
        }
        // 曲线：NIST P-256
        if (!CertificateEvidenceValidator.isP256PublicKey(leaf.getPublicKey())) {
            throw profileReject(CertificateProfileRejectReason.CURVE_NOT_ALLOWED,
                    "Leaf public key curve is not NIST P-256 (secp256r1)");
        }

        // KU：恰好 {digitalSignature, keyAgreement}
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage == null) {
            throw profileReject(CertificateProfileRejectReason.PROFILE_NOT_ALLOWED,
                    "Key usage extension is missing; profile requires digitalSignature + keyAgreement");
        }
        if (!isTrue(keyUsage, 0)) {
            throw profileReject(CertificateProfileRejectReason.DIGITAL_SIGNATURE_MISSING,
                    "KeyUsage lacks digitalSignature");
        }
        if (!isTrue(keyUsage, 4)) {
            throw profileReject(CertificateProfileRejectReason.KEY_AGREEMENT_MISSING,
                    "KeyUsage lacks keyAgreement");
        }
        for (int i = 0; i < keyUsage.length; i++) {
            if (i != 0 && i != 4 && isTrue(keyUsage, i)) {
                throw profileReject(CertificateProfileRejectReason.PROFILE_NOT_ALLOWED,
                        "KeyUsage contains disallowed bit " + i
                                + " (profile allows exactly digitalSignature + keyAgreement)");
            }
        }
        // KU 扩展必须 critical（防降级）
        if (leaf.getCriticalExtensionOIDs() == null
                || !leaf.getCriticalExtensionOIDs().contains(OID_KEY_USAGE)) {
            throw profileReject(CertificateProfileRejectReason.PROFILE_NOT_ALLOWED,
                    "Key usage extension must be critical");
        }

        // EKU：allowlist 仅 clientAuth（FW-SEC-DSN-CR-017 决策：包含 anyEKU/serverAuth/其他
        // 未批准 EKU 即 EKU_POLICY_CONFLICT；仅缺 clientAuth 才 CLIENT_AUTH_MISSING）
        List<String> eku = extendedKeyUsage(leaf);
        if (eku != null) {
            for (String oid : eku) {
                if (!OID_EKU_CLIENT_AUTH.equals(oid)) {
                    throw profileReject(CertificateProfileRejectReason.EKU_POLICY_CONFLICT,
                            "EKU contains disallowed purpose " + oid
                                    + " (v1 allowlist is exactly clientAuth)");
                }
            }
        }
        if (eku == null || !eku.contains(OID_EKU_CLIENT_AUTH)) {
            throw profileReject(CertificateProfileRejectReason.CLIENT_AUTH_MISSING,
                    "EKU lacks clientAuth");
        }

        // 关键扩展：未知关键扩展 fail-closed
        Set<String> criticalOids = leaf.getCriticalExtensionOIDs();
        if (criticalOids != null) {
            for (String oid : criticalOids) {
                if (!KNOWN_CRITICAL_EXTENSIONS.contains(oid)) {
                    throw profileReject(CertificateProfileRejectReason.UNSUPPORTED_CRITICAL_EXTENSION,
                            "Unsupported critical extension: " + oid);
                }
            }
        }

        // 身份绑定：subject 非空且携带 CN，或存在 SAN
        boolean identityBound = hasSubjectCn(leaf) || hasSubjectAltName(leaf);
        if (!identityBound) {
            throw profileReject(CertificateProfileRejectReason.IDENTITY_BINDING_INVALID,
                    "Leaf certificate carries no device identity (no subject CN and no SAN)");
        }

        return new ProfileSemantics(true, true, true, true);
    }

    private CertificateEvidence resolveEvidence(DeviceCertificateRef ref) {
        if (certResolver == null) {
            throw new CertificateProfileVerificationUnavailableException(
                    "CertResolver not configured; cannot resolve TBOX device certificate profile");
        }
        return certResolver.resolve(ref, policy());
    }

    private CertificateResolvePolicy policy() {
        CryptoProperties.KeyprovProfile.CertificateProfile config = properties.getKeyprov().getCertificateProfile();
        return CertificateResolvePolicy.tboxDeviceCertProfile(config.isRequireCertificate(),
                config.isRequireTrustedChain(), config.isRequireGoodStatus());
    }

    private static List<String> extendedKeyUsage(X509Certificate leaf) {
        try {
            return leaf.getExtendedKeyUsage();
        } catch (Exception e) {
            throw profileReject(CertificateProfileRejectReason.EKU_POLICY_CONFLICT,
                    "Failed to read EKU", e);
        }
    }

    private static boolean hasSubjectCn(X509Certificate leaf) {
        if (leaf.getSubjectX500Principal() == null) {
            return false;
        }
        String name = leaf.getSubjectX500Principal().getName();
        if (name == null || name.isBlank()) {
            return false;
        }
        // 含 CN（大小写不敏感）
        return name.toUpperCase(java.util.Locale.ROOT).contains("CN=");
    }

    private static boolean hasSubjectAltName(X509Certificate leaf) {
        try {
            java.util.Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
            return sans != null && !sans.isEmpty();
        } catch (Exception e) {
            // 解析失败：按无 SAN 处理（身份绑定不足 fail-closed）
            return false;
        }
    }

    private static boolean isTrue(boolean[] values, int index) {
        return values != null && values.length > index && values[index];
    }

    private static CertificateProfileRejectedException profileReject(CertificateProfileRejectReason reason,
                                                                     String message) {
        return new CertificateProfileRejectedException(reason, message);
    }

    private static CertificateProfileRejectedException profileReject(CertificateProfileRejectReason reason,
                                                                     String message, Throwable cause) {
        return new CertificateProfileRejectedException(reason, message, cause);
    }
}
