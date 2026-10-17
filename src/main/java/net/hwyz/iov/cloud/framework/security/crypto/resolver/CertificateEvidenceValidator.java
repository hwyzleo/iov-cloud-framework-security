package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertPem;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceMismatchException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import org.springframework.beans.factory.ObjectProvider;

import java.io.ByteArrayInputStream;
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

    public CertificateEvidenceValidator(ObjectProvider<PkiClient> pkiClientProvider,
                                        CryptoProperties properties) {
        this.pkiClientProvider = Objects.requireNonNull(pkiClientProvider, "pkiClientProvider must not be null");
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
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

    // ==================== 校验 ====================

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
        Objects.requireNonNull(evidence, "evidence must not be null");
        Objects.requireNonNull(policy, "policy must not be null");
        Objects.requireNonNull(policy.scenario(), "policy.scenario must not be null");

        byte[] der = evidence.certificateDer();
        if (der == null || der.length == 0) {
            return validateSpkiOnly(evidence, policy);
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
        if (policy.requireGoodStatus()) {
            verifyGoodStatus(der, actualSerial, actualFingerprint);
        }

        return new CertificateEvidence(der, actualSpki, actualSerial, actualFingerprint,
                evidence.chain(), evidence.source());
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
        if (policy.allowedKeyAlgorithms().isEmpty()) {
            return;
        }
        String algorithm = normalizeAlgorithm(publicKey.getAlgorithm());
        boolean allowed = policy.allowedKeyAlgorithms().stream()
                .anyMatch(a -> normalizeAlgorithm(a).equals(algorithm));
        if (!allowed) {
            throw new CertificateMaterialUnavailableException(
                    "Recipient key algorithm is not allowed: " + algorithm);
        }
    }

    private void verifyValidity(X509Certificate leaf) {
        Instant notBefore = leaf.getNotBefore().toInstant();
        Instant notAfter = leaf.getNotAfter().toInstant();
        if (!notAfter.isAfter(notBefore)) {
            throw new CertificateMaterialUnavailableException(
                    "Resolved certificate has an invalid validity period");
        }
        Instant now = Instant.now();
        if (now.isBefore(notBefore) || now.isAfter(notAfter)) {
            throw new CertificateMaterialUnavailableException(
                    "Resolved certificate is expired or not yet valid");
        }
    }

    private void verifyKeyUsage(X509Certificate leaf, CertificateResolvePolicy policy) {
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null) {
            boolean encryptionCapable = isTrue(keyUsage, 2) || isTrue(keyUsage, 4);
            if (!encryptionCapable) {
                throw new CertificateMaterialUnavailableException(
                        "Certificate keyUsage does not permit encryption (keyEncipherment/keyAgreement)");
            }
        }
        if (!policy.requiredExtendedKeyUsage().isEmpty()) {
            List<String> eku;
            try {
                eku = leaf.getExtendedKeyUsage();
            } catch (Exception e) {
                throw new CertificateMaterialUnavailableException("Failed to read certificate EKU", e);
            }
            if (eku == null) {
                throw new CertificateMaterialUnavailableException(
                        "Certificate has no EKU but policy requires: " + policy.requiredExtendedKeyUsage());
            }
            for (String required : policy.requiredExtendedKeyUsage()) {
                if (!eku.contains(required)) {
                    throw new CertificateMaterialUnavailableException(
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
            throw new CertificateMaterialUnavailableException(
                    "Certificate chain is not trusted by crypto.pki.certificate-resolution.trust-anchors-pem", e);
        }
    }

    private void verifyGoodStatus(byte[] der, String serial, String fingerprint) {
        PkiClient pkiClient = pkiClientProvider != null ? pkiClientProvider.getIfAvailable() : null;
        if (pkiClient == null) {
            throw new CertificateMaterialUnavailableException(
                    "Certificate status check is required but no PkiClient is available "
                            + "(enable crypto.pki.revocation.enabled or relax business-key-wrap.require-good-status)");
        }
        PkiClient.CertificateStatusResult result;
        try {
            result = pkiClient.checkCertificateStatus(
                    new PkiClient.CertificateStatusQuery(der, serial, fingerprint, Instant.now()));
        } catch (RuntimeException e) {
            throw new CertificateMaterialUnavailableException(
                    "Certificate status check failed: " + e.getMessage(), e);
        }
        if (result == null || result.revocationState() != PkiClient.RevocationState.GOOD) {
            throw new CertificateMaterialUnavailableException(
                    "Certificate status is not GOOD: "
                            + (result == null ? "null" : result.revocationState()));
        }
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
