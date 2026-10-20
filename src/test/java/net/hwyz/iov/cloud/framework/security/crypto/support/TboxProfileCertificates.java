package net.hwyz.iov.cloud.framework.security.crypto.support;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;

/**
 * 统一 TBOX 设备证书 Profile 测试证书生成器（FW-SEC-DSN-CR-017 §12）。
 * <p>
 * 生成带任意 KU/EKU/CA/关键扩展/身份的叶子证书，供 Profile 校验正负向矩阵使用。
 * <p>
 * 有效期相对 {@link #REFERENCE_INSTANT} 固定参考时刻生成（与测试注入的固定 Clock
 * {@code 2026-10-20T10:00:00Z} 对齐），<strong>不得</strong>使用 {@code REFERENCE_INSTANT}：
 * 否则证书有效期与真实墙钟耦合，墙钟越过参考时刻 +1h 后所有新证书 notBefore 晚于固定
 * Clock，统一证据校验将先抛 CERTIFICATE_NOT_YET_VALID 导致全矩阵误挂。
 */
public final class TboxProfileCertificates {

    /** 固定参考时刻：证书有效期基准（比测试固定 Clock 早 1 小时，保证 at 10:00:00Z 始终有效）。 */
    private static final Instant REFERENCE_INSTANT = Instant.parse("2026-10-20T09:00:00Z");

    public static final X500Name TBOX_SUBJECT = new X500Name("CN=TBOX-00000000000000000000000000000001");
    public static final X500Name NO_CN_SUBJECT = new X500Name("O=OpenIOV");

    /** 未知关键扩展 OID（测试 UNSUPPORTED_CRITICAL_EXTENSION）。 */
    public static final String UNKNOWN_CRITICAL_OID = "1.2.3.4.5.6.7.8.9";

    private TboxProfileCertificates() {
    }

    public record Leaf(KeyPair keyPair, X509Certificate certificate) {

        public byte[] der() throws Exception {
            return certificate.getEncoded();
        }
    }

    /** P-256 双 KU + clientAuth + CA=false + 身份（正向）。 */
    public static Leaf positive() throws Exception {
        return build(TBOX_SUBJECT, p256(), false, KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** P-256 双 KU + clientAuth + CA=true。 */
    public static Leaf caTrue() throws Exception {
        return build(TBOX_SUBJECT, p256(), true, KeyUsage.keyCertSign,
                true, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** RSA 2048 双 KU + clientAuth。 */
    public static Leaf rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return build(TBOX_SUBJECT, kpg.generateKeyPair(), false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** P-384 双 KU + clientAuth。 */
    public static Leaf p384() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        return build(TBOX_SUBJECT, kpg.generateKeyPair(), false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 仅 digitalSignature。 */
    public static Leaf digitalSignatureOnly() throws Exception {
        return build(TBOX_SUBJECT, p256(), false, KeyUsage.digitalSignature,
                true, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 仅 keyAgreement。 */
    public static Leaf keyAgreementOnly() throws Exception {
        return build(TBOX_SUBJECT, p256(), false, KeyUsage.keyAgreement,
                true, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 双 KU + serverAuth EKU。 */
    public static Leaf serverAuthEku() throws Exception {
        return build(TBOX_SUBJECT, p256(), false, KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, KeyPurposeId.id_kp_serverAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 双 KU + anyExtendedKeyUsage。 */
    public static Leaf anyEku() throws Exception {
        return build(TBOX_SUBJECT, p256(), false, KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, KeyPurposeId.anyExtendedKeyUsage, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 双 KU、无 EKU。 */
    public static Leaf noEku() throws Exception {
        return build(TBOX_SUBJECT, p256(), false, KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, null, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 双 KU + clientAuth + KU 非 critical。 */
    public static Leaf kuNonCritical() throws Exception {
        return build(TBOX_SUBJECT, p256(), false, KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                false, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 双 KU + clientAuth + 额外 keyEncipherment 位。 */
    public static Leaf extraKuBit() throws Exception {
        return build(TBOX_SUBJECT, p256(), false,
                KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.keyEncipherment,
                true, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 双 KU + clientAuth + subject 无 CN/SAN（身份绑定不足）。 */
    public static Leaf noIdentity() throws Exception {
        return build(NO_CN_SUBJECT, p256(), false, KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 双 KU + clientAuth + 未知关键扩展。 */
    public static Leaf unknownCriticalExtension() throws Exception {
        return build(TBOX_SUBJECT, p256(), false, KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, KeyPurposeId.id_kp_clientAuth, true,
                REFERENCE_INSTANT.minusSeconds(3600), REFERENCE_INSTANT.plusSeconds(24 * 3600));
    }

    /** 双 KU + clientAuth + 自定义有效期（过期测试）。 */
    public static Leaf expired() throws Exception {
        return build(TBOX_SUBJECT, p256(), false, KeyUsage.digitalSignature | KeyUsage.keyAgreement,
                true, KeyPurposeId.id_kp_clientAuth, false,
                REFERENCE_INSTANT.minusSeconds(48 * 3600), REFERENCE_INSTANT.minusSeconds(24 * 3600));
    }

    private static KeyPair p256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static Leaf build(X500Name subject, KeyPair keyPair, boolean ca, int keyUsageBits,
                              boolean kuCritical, KeyPurposeId eku, boolean unknownCritical,
                              Instant notBefore, Instant notAfter) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                TBOX_SUBJECT, BigInteger.valueOf(System.nanoTime()),
                Date.from(notBefore), Date.from(notAfter), subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, kuCritical, new KeyUsage(keyUsageBits));
        if (eku != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        }
        if (unknownCritical) {
            builder.addExtension(new ASN1ObjectIdentifier(UNKNOWN_CRITICAL_OID), true,
                    new DEROctetString(new byte[]{0x01}));
        }
        X509CertificateHolder holder = builder.build(
                new JcaContentSignerBuilder(signerAlgorithm(keyPair)).build(keyPair.getPrivate()));
        return new Leaf(keyPair, new JcaX509CertificateConverter().getCertificate(holder));
    }

    private static String signerAlgorithm(KeyPair keyPair) {
        return "RSA".equals(keyPair.getPrivate().getAlgorithm())
                ? "SHA256withRSA" : "SHA256withECDSA";
    }
}
