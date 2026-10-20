package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectReason;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceCertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.ValidatedTboxDeviceCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import java.util.Set;

/**
 * 统一 TBOX 设备证书 Profile 能力声明与自检（FW-SEC-DSN-CR-017 §9）。
 * <p>
 * 新增 capability {@link #TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1}：公开
 * {@code TboxDeviceCertificateValidator} 可调用、P-256/双 KU/clientAuth/CA=false/关键扩展/
 * 身份绑定正负向 fixtures 全部通过。
 * <p>
 * 关闭（{@code crypto.keyprov.certificate-profile.enabled=false}）时<strong>不</strong>声明
 * 本 capability（{@link #supports} 恒 false），完整 {@code KEYPROV_ECDH_ES_V1_READY}
 * 聚合门禁由 {@link KeyprovReadiness} 统一控制，禁止单边 READY 被 VMD 解释为完整能力。
 */
public final class KeyprovCertificateProfileCapability {

    /** 统一 TBOX 设备证书 Profile 能力标识（FW-SEC-DSN-CR-017 §9）。 */
    public static final String TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1 =
            "TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1";

    private static final Set<String> SUPPORTED = Set.of(TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1);

    private KeyprovCertificateProfileCapability() {
    }

    /**
     * 本 artifact 声明支持的能力集合（Profile 能力随装配开关动态生效，见 {@link #supports}）。
     */
    public static Set<String> supported() {
        return SUPPORTED;
    }

    /**
     * 是否声明支持指定能力。
     * <p>
     * Profile 能力仅在装配开启（{@code crypto.keyprov.certificate-profile.enabled=true}）
     * 且自检通过时声明（FW-SEC-DSN-CR-017 决策 3）；关闭时恒 false。
     *
     * @param capability       能力标识
     * @param profileAssembled Profile 组件是否装配
     */
    public static boolean supports(String capability, boolean profileAssembled) {
        return profileAssembled && capability != null && SUPPORTED.contains(capability);
    }

    /**
     * 公开 {@code TboxDeviceCertificateValidator#validate(DeviceCertificateRef, DeviceCertificateProfile)}
     * 是否可调用。
     */
    public static boolean publicApiAvailable() {
        try {
            Method validate = TboxDeviceCertificateValidator.class.getMethod(
                    "validate", DeviceCertificateRef.class, DeviceCertificateProfile.class);
            return Modifier.isPublic(validate.getModifiers())
                    && validate.getReturnType() == ValidatedTboxDeviceCertificate.class;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    /**
     * 能力静态自检（不依赖 Spring 上下文）：公开 API + 固定 Profile 语义正负向向量。
     *
     * @return READY 返回 true
     */
    public static boolean selfCheckReady() {
        return publicApiAvailable() && profileVectorsReady();
    }

    /**
     * Profile 语义冻结向量自检（FW-SEC-DSN-CR-017 §9/§12）：
     * 正向 P-256 双 KU + clientAuth 通过；RSA、P-384、CA=true、单 KU、缺 clientAuth、
     * serverAuth/anyEKU 冲突、缺身份、未知关键扩展均按预期 reason 拒绝。
     */
    static boolean profileVectorsReady() {
        try {
            if (!expectPass(positiveLeaf())) {
                return false;
            }
            return expectReject(rsaLeaf(), CertificateProfileRejectReason.PUBLIC_KEY_ALGORITHM_NOT_ALLOWED)
                    && expectReject(p384Leaf(), CertificateProfileRejectReason.CURVE_NOT_ALLOWED)
                    && expectReject(caLeaf(), CertificateProfileRejectReason.NOT_END_ENTITY)
                    && expectReject(kuDigitalSignatureOnlyLeaf(), CertificateProfileRejectReason.KEY_AGREEMENT_MISSING)
                    && expectReject(kuKeyAgreementOnlyLeaf(), CertificateProfileRejectReason.DIGITAL_SIGNATURE_MISSING)
                    && expectReject(serverAuthLeaf(), CertificateProfileRejectReason.EKU_POLICY_CONFLICT)
                    && expectReject(anyEkuLeaf(), CertificateProfileRejectReason.EKU_POLICY_CONFLICT)
                    && expectReject(noEkuLeaf(), CertificateProfileRejectReason.CLIENT_AUTH_MISSING)
                    && expectReject(noIdentityLeaf(), CertificateProfileRejectReason.IDENTITY_BINDING_INVALID)
                    && expectReject(unknownCriticalLeaf(), CertificateProfileRejectReason.UNSUPPORTED_CRITICAL_EXTENSION);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean expectPass(X509Certificate leaf) {
        try {
            return DefaultTboxDeviceCertificateValidator.evaluateProfile(
                    leaf, DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1) != null;
        } catch (CertificateProfileRejectedException e) {
            return false;
        }
    }

    private static boolean expectReject(X509Certificate leaf, CertificateProfileRejectReason expected) {
        try {
            DefaultTboxDeviceCertificateValidator.evaluateProfile(
                    leaf, DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1);
            return false;
        } catch (CertificateProfileRejectedException e) {
            return e.rejectReason() == expected;
        }
    }

    // ==================== 自检 fixtures（运行时生成，不依赖生产证书） ====================

    private static X509Certificate positiveLeaf() throws Exception {
        return buildLeaf(p256KeyPair(), CN_SUBJECT, false, KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, KeyPurposeId.id_kp_clientAuth, false);
    }

    private static X509Certificate rsaLeaf() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return buildLeaf(kpg.generateKeyPair(), CN_SUBJECT, false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement, true,
                KeyPurposeId.id_kp_clientAuth, false);
    }

    private static X509Certificate p384Leaf() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        return buildLeaf(kpg.generateKeyPair(), CN_SUBJECT, false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement, true,
                KeyPurposeId.id_kp_clientAuth, false);
    }

    private static X509Certificate caLeaf() throws Exception {
        return buildCaLeaf(p256KeyPair(), true, KeyPurposeId.id_kp_clientAuth);
    }

    private static X509Certificate kuDigitalSignatureOnlyLeaf() throws Exception {
        return buildLeaf(p256KeyPair(), CN_SUBJECT, false, KeyUsage.digitalSignature, true,
                KeyPurposeId.id_kp_clientAuth, false);
    }

    private static X509Certificate kuKeyAgreementOnlyLeaf() throws Exception {
        return buildLeaf(p256KeyPair(), CN_SUBJECT, false, KeyUsage.keyAgreement, true,
                KeyPurposeId.id_kp_clientAuth, false);
    }

    private static X509Certificate serverAuthLeaf() throws Exception {
        return buildLeaf(p256KeyPair(), CN_SUBJECT, false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement, true,
                KeyPurposeId.id_kp_serverAuth, false);
    }

    private static X509Certificate anyEkuLeaf() throws Exception {
        return buildLeaf(p256KeyPair(), CN_SUBJECT, false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement, true,
                KeyPurposeId.anyExtendedKeyUsage, false);
    }

    private static X509Certificate noEkuLeaf() throws Exception {
        return buildLeaf(p256KeyPair(), CN_SUBJECT, false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement, true, null, false);
    }

    private static X509Certificate noIdentityLeaf() throws Exception {
        // subject 无 CN 且无 SAN → IDENTITY_BINDING_INVALID
        return buildLeaf(p256KeyPair(), new X500Name("O=OpenIOV"), false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement, true,
                KeyPurposeId.id_kp_clientAuth, false);
    }

    private static X509Certificate unknownCriticalLeaf() throws Exception {
        return buildLeaf(p256KeyPair(), CN_SUBJECT, false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement, true,
                KeyPurposeId.id_kp_clientAuth, true);
    }

    private static KeyPair p256KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static final X500Name CN_SUBJECT = new X500Name("CN=TBOX-PROFILE-SELF-CHECK");

    private static final String UNKNOWN_CRITICAL_OID = "1.2.3.4.5.6.7.8.9";

    private static X509Certificate buildLeaf(KeyPair keyPair, X500Name subject, boolean ca,
                                             int keyUsageBits, boolean kuCritical,
                                             KeyPurposeId eku, boolean unknownCritical) throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(24 * 3600));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                CN_SUBJECT, BigInteger.valueOf(System.nanoTime()), notBefore, notAfter,
                subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, kuCritical, new KeyUsage(keyUsageBits));
        if (eku != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        }
        if (unknownCritical) {
            builder.addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier(UNKNOWN_CRITICAL_OID),
                    true, new org.bouncycastle.asn1.DEROctetString(new byte[]{0x01}));
        }
        return toCertificate(builder.build(
                new JcaContentSignerBuilder(signerAlgorithm(keyPair)).build(keyPair.getPrivate())));
    }

    private static X509Certificate buildCaLeaf(KeyPair keyPair, boolean ca,
                                               KeyPurposeId eku) throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(24 * 3600));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                CN_SUBJECT, BigInteger.valueOf(System.nanoTime()), notBefore, notAfter,
                CN_SUBJECT, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        if (eku != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        }
        return toCertificate(builder.build(
                new JcaContentSignerBuilder(signerAlgorithm(keyPair)).build(keyPair.getPrivate())));
    }

    private static String signerAlgorithm(KeyPair keyPair) {
        return "RSA".equals(keyPair.getPrivate().getAlgorithm())
                ? "SHA256withRSA" : "SHA256withECDSA";
    }

    private static X509Certificate toCertificate(org.bouncycastle.cert.X509CertificateHolder holder)
            throws Exception {
        return new JcaX509CertificateConverter().getCertificate(holder);
    }
}
