package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertPem;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceMismatchException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import org.springframework.beans.factory.ObjectProvider;

import java.io.ByteArrayInputStream;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * 统一证书证据解析 / 校验器（FW-SEC-DSN-CR-012 §5/§6）。
 * <p>
 * 公共校验权威：对解析到的材料统一执行编码、算法白名单、serial/fingerprint 一致性、
 * 证书链/issuer、有效期、KU/EKU 与（按策略）吊销状态校验。自定义 {@link CertResolver}
 * 的输出亦须经本类校验后方可使用。
 * <p>
 * 已校验证据<b>不缓存</b>（本期每次重新解析校验，保证状态 freshness 与失效语义正确）。
 * 信任锚必须显式配置 {@code crypto.pki.certificate-resolution.trust-anchors-pem}，
 * 不接受从 TLS 传输信任或吊销查询 issuer 隐式回退。
 */
public class CertificateEvidenceValidator {

    private final ObjectProvider<PkiClient> pkiClientProvider;
    private final CryptoProperties properties;
    private final Clock clock;

    public CertificateEvidenceValidator(ObjectProvider<PkiClient> pkiClientProvider,
                                        CryptoProperties properties) {
        this(pkiClientProvider, properties, Clock.systemUTC());
    }

    /**
     * 使用框架受信任 {@link Clock} 的构造器（FW-SEC-DSN-CR-016 §3）。
     * <p>
     * 证书有效期与吊销状态 freshness 统一取 {@code clock.instant()}，调用方不得以任意历史时间
     * 绕过证书状态；测试可通过注入固定 Clock 保证确定性。
     *
     * @param pkiClientProvider PKI 客户端提供者
     * @param properties        配置属性
     * @param clock             受信任时钟（为 null 时回退系统 UTC 时钟）
     */
    public CertificateEvidenceValidator(ObjectProvider<PkiClient> pkiClientProvider,
                                        CryptoProperties properties, Clock clock) {
        this.pkiClientProvider = Objects.requireNonNull(pkiClientProvider, "pkiClientProvider must not be null");
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    // ==================== 解析（不校验） ====================

    /**
     * 从叶子证书 DER 解析出规范化证据（serial/fingerprint/SPKI）。
     */
    public static CertificateEvidence fromCertificateDer(byte[] certificateDer, EvidenceSource source) {
        return fromCertificateDer(certificateDer, List.of(), source);
    }

    /**
     * 从叶子证书 DER + 证书链解析出规范化证据。
     */
    public static CertificateEvidence fromCertificateDer(byte[] certificateDer, List<byte[]> chain,
                                                         EvidenceSource source) {
        if (certificateDer == null || certificateDer.length == 0) {
            throw new CertificateMaterialUnavailableException("Leaf certificate DER is empty");
        }
        X509Certificate cert = parse(certificateDer);
        return new CertificateEvidence(
                certificateDer,
                cert.getPublicKey().getEncoded(),
                PkiClient.canonicalSerial(cert.getSerialNumber().toString(16)),
                sha256Hex(certificateDer),
                chain,
                source);
    }

    /**
     * 从公钥 SPKI 解析出证据（无证书，仅 policy 允许裸公钥时可用）。
     */
    public static CertificateEvidence fromSpki(byte[] spki, String declaredFingerprint, EvidenceSource source) {
        if (spki == null || spki.length == 0) {
            throw new CertificateMaterialUnavailableException("SPKI is empty");
        }
        String fingerprint = PkiClient.normalizeFingerprint(declaredFingerprint);
        if (fingerprint == null) {
            fingerprint = sha256Hex(spki);
        }
        return new CertificateEvidence(null, spki, null, fingerprint, List.of(), source);
    }

    /**
     * 解析公钥 SPKI 的公钥算法（{@code EC} / {@code RSA} / {@code Ed25519}）；
     * 供收方套件推导（FW-SEC-DSN-CR-014 §7.1）使用。无法解析时抛
     * {@link CertificateMaterialUnavailableException}（fail-closed）。
     *
     * @param spki 公钥 SPKI DER
     * @return 公钥算法
     */
    public static String publicKeyAlgorithm(byte[] spki) {
        return parsePublicKey(spki).getAlgorithm();
    }

    // ==================== 校验 ====================

    /**
     * 校验结果：规范化证据 + 吊销状态 freshness（FW-SEC-DSN-CR-017 §4）。
     *
     * @param evidence        已校验的规范化证据
     * @param statusFreshUntil 吊销状态 freshness 截止（来自 status 响应 nextUpdate；
     *                        {@code null} 仅表示不可缓存，不代表状态永久有效）
     */
    public record ValidatedCertificate(CertificateEvidence evidence, Instant statusFreshUntil) {
    }

    /**
     * 按调用场景策略统一校验证据。
     *
     * @param evidence 解析出的证据
     * @param ref      原始引用（用于声明字段一致性比对，可空）
     * @param policy   场景策略
     * @return 规范化后的已校验证据
     */
    public CertificateEvidence validate(CertificateEvidence evidence, DeviceCertificateRef ref,
                                        CertificateResolvePolicy policy) {
        return validateInternal(evidence, ref, policy).evidence();
    }

    /**
     * 按调用场景策略统一校验证据，并返回吊销状态 freshness（FW-SEC-DSN-CR-017）。
     * <p>
     * 供统一 TBOX 设备证书 Profile 验证器消费（{@code statusFreshUntil} = status 响应
     * {@code nextUpdate}，无吊销组件/无 nextUpdate 时为 {@code null}，仅表示不可缓存，
     * 不代表状态永久有效）。
     *
     * @param evidence 解析出的证据
     * @param ref      原始引用（用于声明字段一致性比对，可空）
     * @param policy   场景策略
     * @return 规范化后的已校验证据 + 状态 freshness
     */
    public ValidatedCertificate validateWithFreshness(CertificateEvidence evidence, DeviceCertificateRef ref,
                                                      CertificateResolvePolicy policy) {
        return validateInternal(evidence, ref, policy);
    }

    private ValidatedCertificate validateInternal(CertificateEvidence evidence, DeviceCertificateRef ref,
                                                  CertificateResolvePolicy policy) {
        Objects.requireNonNull(evidence, "evidence must not be null");
        Objects.requireNonNull(policy, "policy must not be null");
        Objects.requireNonNull(policy.scenario(), "policy.scenario must not be null");

        byte[] der = evidence.certificateDer();
        if (der == null || der.length == 0) {
            return new ValidatedCertificate(validateSpkiOnly(evidence, policy), null);
        }

        X509Certificate leaf = parse(der);
        String actualSerial = PkiClient.canonicalSerial(leaf.getSerialNumber().toString(16));
        String actualFingerprint = sha256Hex(der);
        byte[] actualSpki = leaf.getPublicKey().getEncoded();

        verifyDeclaredConsistency(actualSerial, actualFingerprint, evidence, ref);
        verifyKeyAlgorithm(leaf.getPublicKey(), policy);
        verifyValidity(leaf);
        verifyKeyUsage(leaf, policy);
        if (policy.requireTrustedChain()) {
            verifyTrustedChain(leaf, evidence.chain());
        }
        Instant statusFreshUntil = null;
        if (policy.requireGoodStatus()) {
            statusFreshUntil = verifyGoodStatusWithFreshness(der, actualSerial, actualFingerprint);
        }

        CertificateEvidence validated = new CertificateEvidence(der, actualSpki, actualSerial, actualFingerprint,
                evidence.chain(), evidence.source());
        return new ValidatedCertificate(validated, statusFreshUntil);
    }

    private CertificateEvidence validateSpkiOnly(CertificateEvidence evidence,
                                                 CertificateResolvePolicy policy) {
        if (!policy.allowBareSpki()) {
            throw new CertificateMaterialUnavailableException(
                    "Leaf certificate DER is required by " + policy.scenario() + " policy");
        }
        byte[] spki = evidence.spki();
        if (spki == null || spki.length == 0) {
            throw new CertificateMaterialUnavailableException(
                    "No leaf certificate DER or public key SPKI available for " + policy.scenario());
        }
        String actualFingerprint = sha256Hex(spki);
        String declared = PkiClient.normalizeFingerprint(evidence.sha256Fingerprint());
        if (declared != null && !declared.equals(actualFingerprint)) {
            throw new CertificateEvidenceMismatchException(
                    "Declared sha256 fingerprint does not match the provided SPKI");
        }
        verifyKeyAlgorithm(parsePublicKey(spki), policy);
        return new CertificateEvidence(null, spki, null, actualFingerprint, evidence.chain(),
                evidence.source());
    }

    private void verifyDeclaredConsistency(String actualSerial, String actualFingerprint,
                                           CertificateEvidence evidence, DeviceCertificateRef ref) {
        if (evidence.serial() != null) {
            String canonicalEvidenceSerial = canonicalOrNull(evidence.serial());
            if (canonicalEvidenceSerial == null || !canonicalEvidenceSerial.equals(actualSerial)) {
                throw new CertificateEvidenceMismatchException(
                        "Certificate serial does not match the declared/evidence serial");
            }
        }
        if (evidence.sha256Fingerprint() != null) {
            String declared = PkiClient.normalizeFingerprint(evidence.sha256Fingerprint());
            if (declared != null && !declared.equals(actualFingerprint)) {
                throw new CertificateEvidenceMismatchException(
                        "Certificate fingerprint does not match the declared fingerprint");
            }
        }
        if (ref == null) {
            return;
        }
        if (ref.certSerial() != null && !ref.certSerial().isBlank()) {
            String declaredSerial = canonicalOrNull(ref.certSerial());
            if (declaredSerial == null || !declaredSerial.equals(actualSerial)) {
                throw new CertificateEvidenceMismatchException(
                        "Resolved certificate serial does not match the requested certSerial");
            }
        }
        if (ref.sha256Fingerprint() != null && !ref.sha256Fingerprint().isBlank()) {
            String declared = PkiClient.normalizeFingerprint(ref.sha256Fingerprint());
            if (declared != null && !declared.equals(actualFingerprint)) {
                throw new CertificateEvidenceMismatchException(
                        "Resolved certificate fingerprint does not match the requested fingerprint");
            }
        }
    }

    private void verifyKeyAlgorithm(PublicKey publicKey, CertificateResolvePolicy policy) {
        if (!policy.allowedKeyAlgorithms().isEmpty()) {
            String algorithm = normalizeAlgorithm(publicKey.getAlgorithm());
            boolean allowed = policy.allowedKeyAlgorithms().stream()
                    .anyMatch(a -> normalizeAlgorithm(a).equals(algorithm));
            if (!allowed) {
                throw new CertificateEvidenceRejectedException(
                        CertificateEvidenceRejectedException.Reason.KEY_ALGORITHM_NOT_ALLOWED,
                        "Recipient key algorithm is not allowed: " + algorithm);
            }
        }
        // FW-SEC-DSN-CR-014 §7.1：业务密钥封装场景的 EC 收方必须为 NIST P-256。
        // FW-SEC-DSN-CR-016 §4：导入证明验签场景的 EC 设备证书同样必须为 NIST P-256。
        if ((policy.scenario() == CertificateResolvePolicy.Scenario.BUSINESS_KEY_WRAP
                || policy.scenario() == CertificateResolvePolicy.Scenario.IMPORT_PROOF_VERIFY)
                && publicKey instanceof ECPublicKey ecPublicKey
                && !isP256(ecPublicKey)) {
            throw new CertificateEvidenceRejectedException(
                    CertificateEvidenceRejectedException.Reason.CURVE_NOT_ALLOWED,
                    "EC certificate must use NIST P-256 (secp256r1) for " + policy.scenario());
        }
    }

    /**
     * 是否为 NIST P-256 (secp256r1) 公钥。
     */
    private static boolean isP256(ECPublicKey publicKey) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec p256 = parameters.getParameterSpec(ECParameterSpec.class);
            ECParameterSpec actual = publicKey.getParams();
            return actual.getCurve().getField().getFieldSize() == 256
                    && p256.getOrder().equals(actual.getOrder())
                    && p256.getGenerator().equals(actual.getGenerator())
                    && p256.getCofactor() == actual.getCofactor();
        } catch (Exception e) {
            return false;
        }
    }

    private void verifyValidity(X509Certificate leaf) {
        Instant notBefore = leaf.getNotBefore().toInstant();
        Instant notAfter = leaf.getNotAfter().toInstant();
        if (!notAfter.isAfter(notBefore)) {
            throw new CertificateEvidenceRejectedException(
                    CertificateEvidenceRejectedException.Reason.CERTIFICATE_VALIDITY_INVALID,
                    "Resolved certificate has an invalid validity period");
        }
        Instant now = clock.instant();
        if (now.isBefore(notBefore)) {
            throw new CertificateEvidenceRejectedException(
                    CertificateEvidenceRejectedException.Reason.CERTIFICATE_NOT_YET_VALID,
                    "Resolved certificate is not yet valid");
        }
        if (now.isAfter(notAfter)) {
            throw new CertificateEvidenceRejectedException(
                    CertificateEvidenceRejectedException.Reason.CERTIFICATE_EXPIRED,
                    "Resolved certificate is expired");
        }
    }

    /**
     * 证书用途校验（FW-SEC-DSN-CR-014 §7.1）。
     * <p>
     * EC 收方证书必须具备 {@code keyAgreement}；RSA 收方证书必须具备 {@code keyEncipherment}。
     * {@code digitalSignature} 不等价于 {@code keyAgreement}。确定性策略不匹配直接抛出
     * {@link CertificateEvidenceRejectedException}（不可重试），
     * <strong>不得</strong>包装为 {@link CertificateMaterialUnavailableException}。
     */
    private void verifyKeyUsage(X509Certificate leaf, CertificateResolvePolicy policy) {
        boolean[] keyUsage = leaf.getKeyUsage();
        if (policy.scenario() == CertificateResolvePolicy.Scenario.TBOX_DEVICE_CERT_PROFILE) {
            // 统一 Profile（FW-SEC-DSN-CR-017 RD-017-1/RD-017-4）：单场景 KU/EKU 不在本层收紧，
            // CA=false、P-256、双 KU（digitalSignature+keyAgreement）、clientAuth、关键扩展与
            // 身份绑定由 DefaultTboxDeviceCertificateValidator 分项校验并给出稳定 reason。
            return;
        }
        if (policy.scenario() == CertificateResolvePolicy.Scenario.IMPORT_PROOF_VERIFY) {
            // FW-SEC-DSN-CR-016 §4/§6：导入证明验签要求设备证书 KeyUsage 含 digitalSignature。
            if (keyUsage != null && !isTrue(keyUsage, 0)) {
                throw new CertificateEvidenceRejectedException(
                        CertificateEvidenceRejectedException.Reason.KEY_USAGE_NOT_PERMITTED,
                        "Device certificate must have digitalSignature for import-proof verification");
            }
        } else if (keyUsage != null) {
            PublicKey publicKey = leaf.getPublicKey();
            if (publicKey instanceof ECPublicKey) {
                if (!isTrue(keyUsage, 4)) {
                    throw new CertificateEvidenceRejectedException(
                            CertificateEvidenceRejectedException.Reason.KEY_USAGE_NOT_PERMITTED,
                            "EC recipient certificate must have keyAgreement for ECDH-ES wrap");
                }
            } else if (publicKey instanceof RSAPublicKey) {
                if (!isTrue(keyUsage, 2)) {
                    throw new CertificateEvidenceRejectedException(
                            CertificateEvidenceRejectedException.Reason.KEY_USAGE_NOT_PERMITTED,
                            "RSA recipient certificate must have keyEncipherment for RSA-OAEP wrap");
                }
            } else {
                throw new CertificateEvidenceRejectedException(
                        CertificateEvidenceRejectedException.Reason.UNSUPPORTED_RECIPIENT_KEY,
                        "Unsupported recipient key type for key wrap: " + publicKey.getAlgorithm());
            }
        }
        if (!policy.requiredExtendedKeyUsage().isEmpty()) {
            List<String> eku;
            try {
                eku = leaf.getExtendedKeyUsage();
            } catch (Exception e) {
                throw new CertificateEvidenceRejectedException(
                        CertificateEvidenceRejectedException.Reason.EXTENDED_KEY_USAGE_NOT_PERMITTED,
                        "Failed to read certificate EKU", e);
            }
            if (eku == null) {
                throw new CertificateEvidenceRejectedException(
                        CertificateEvidenceRejectedException.Reason.EXTENDED_KEY_USAGE_NOT_PERMITTED,
                        "Certificate has no EKU but policy requires: " + policy.requiredExtendedKeyUsage());
            }
            for (String required : policy.requiredExtendedKeyUsage()) {
                if (!eku.contains(required)) {
                    throw new CertificateEvidenceRejectedException(
                            CertificateEvidenceRejectedException.Reason.EXTENDED_KEY_USAGE_NOT_PERMITTED,
                            "Certificate EKU does not contain required purpose: " + required);
                }
            }
        }
    }

    private void verifyTrustedChain(X509Certificate leaf, List<byte[]> chain) {
        List<X509Certificate> anchors = parseTrustAnchors();
        if (anchors.isEmpty()) {
            throw new CertificateMaterialUnavailableException(
                    "crypto.pki.certificate-resolution.trust-anchors-pem is required to verify the "
                            + "certificate chain; no implicit fallback to TLS/revocation trust anchors");
        }
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate anchor : anchors) {
            trustAnchors.add(new TrustAnchor(anchor, null));
            if (anchor.equals(leaf)) {
                return;
            }
        }

        List<X509Certificate> candidates = new ArrayList<>();
        candidates.add(leaf);
        if (chain != null) {
            for (byte[] element : chain) {
                if (element == null || element.length == 0) {
                    continue;
                }
                X509Certificate certificate = parse(element);
                if (!certificate.equals(leaf)) {
                    candidates.add(certificate);
                }
            }
        }

        try {
            CertStore certStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(candidates));
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(leaf);
            PKIXBuilderParameters parameters = new PKIXBuilderParameters(trustAnchors, selector);
            parameters.setRevocationEnabled(false);
            parameters.addCertStore(certStore);
            CertPathBuilder.getInstance("PKIX").build(parameters);
        } catch (Exception e) {
            // 链不可信是证书固有属性：确定性、不可重试（FW-SEC-DSN-CR-014 §7.2）。
            throw new CertificateEvidenceRejectedException(
                    CertificateEvidenceRejectedException.Reason.CHAIN_NOT_TRUSTED,
                    "Certificate chain is not trusted by crypto.pki.certificate-resolution.trust-anchors-pem", e);
        }
    }

    /**
     * 吊销状态校验并返回 status freshness（FW-SEC-DSN-CR-017 §4）。
     *
     * @param der         叶子证书 DER
     * @param serial      规范化 serial
     * @param fingerprint SHA-256 指纹
     * @return status 响应 {@code nextUpdate}（无则 {@code null}，仅表示不可缓存）
     */
    private Instant verifyGoodStatusWithFreshness(byte[] der, String serial, String fingerprint) {
        PkiClient pkiClient = pkiClientProvider != null ? pkiClientProvider.getIfAvailable() : null;
        if (pkiClient == null) {
            throw new CertificateMaterialUnavailableException(
                    "Certificate status check is required but no PkiClient is available "
                            + "(enable crypto.pki.revocation.enabled or relax business-key-wrap.require-good-status)");
        }
        PkiClient.CertificateStatusResult result;
        try {
            result = pkiClient.checkCertificateStatus(
                    new PkiClient.CertificateStatusQuery(der, serial, fingerprint, clock.instant()));
        } catch (RuntimeException e) {
            // OCSP/CRL 暂时不可达：依赖不可用、可重试（FW-SEC-DSN-CR-014 §7.2）。
            throw new CertificateMaterialUnavailableException(
                    "Certificate status check failed: " + e.getMessage(), e);
        }
        if (result != null && result.revocationState() == PkiClient.RevocationState.REVOKED) {
            // 已吊销是证书固有属性：确定性、不可重试。
            throw new CertificateEvidenceRejectedException(
                    CertificateEvidenceRejectedException.Reason.CERTIFICATE_REVOKED,
                    "Resolved certificate is REVOKED");
        }
        if (result == null || result.revocationState() != PkiClient.RevocationState.GOOD) {
            // UNKNOWN：无法证明 GOOD，按依赖不可用（可重试）处理。
            throw new CertificateMaterialUnavailableException(
                    "Certificate status is not GOOD: "
                            + (result == null ? "null" : result.revocationState()));
        }
        // GOOD：返回 nextUpdate 作 freshness 截止；无 nextUpdate 返回 null（仅表示不可缓存）。
        return result.nextUpdate();
    }

    // ==================== 工具 ====================

    private List<X509Certificate> parseTrustAnchors() {
        String pem = properties.getPki().getCertificateResolution().getTrustAnchorsPem();
        if (pem == null || pem.isBlank()) {
            return List.of();
        }
        List<X509Certificate> anchors = new ArrayList<>();
        for (byte[] der : CertPem.parsePemBundle(pem)) {
            anchors.add(parse(der));
        }
        return anchors;
    }

    private static X509Certificate parse(byte[] der) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new CertificateMaterialUnavailableException("Failed to parse certificate DER", e);
        }
    }

    /**
     * 解析叶子证书 DER（FW-SEC-DSN-CR-017 §5 复用，避免 Profile 验证器重复解析）。
     * <p>
     * 仅解析叶子，<strong>不</strong>解析证书链（链校验仍由 {@link #verifyTrustedChain} 唯一负责）。
     *
     * @param certificateDer 叶子证书 DER
     * @return 叶子证书
     * @throws CertificateMaterialUnavailableException DER 非法（fail-closed）
     */
    public static X509Certificate parseLeaf(byte[] certificateDer) {
        return parse(certificateDer);
    }

    /**
     * 是否为 NIST P-256 (secp256r1) 公钥（FW-SEC-DSN-CR-017 RD-017-1）。
     *
     * @param publicKey 公钥
     * @return true 表示 NIST P-256
     */
    public static boolean isP256PublicKey(PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey ecPublicKey)) {
            return false;
        }
        return isP256(ecPublicKey);
    }

    private static PublicKey parsePublicKey(byte[] spki) {
        for (String algorithm : new String[]{"RSA", "EC", "Ed25519"}) {
            try {
                return java.security.KeyFactory.getInstance(algorithm)
                        .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
            } catch (Exception ignored) {
                // try next algorithm
            }
        }
        throw new CertificateMaterialUnavailableException("Unsupported or malformed public key SPKI");
    }

    private static boolean isTrue(boolean[] values, int index) {
        return values != null && values.length > index && values[index];
    }

    private static String canonicalOrNull(String serial) {
        try {
            return PkiClient.canonicalSerial(serial);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String normalizeAlgorithm(String algorithm) {
        if (algorithm == null) {
            return "";
        }
        String normalized = algorithm.trim().toUpperCase(Locale.ROOT);
        if (normalized.equals("EDDSA") || normalized.equals("ED25519")) {
            return "ED25519";
        }
        return normalized;
    }

    private static String sha256Hex(byte[] data) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
