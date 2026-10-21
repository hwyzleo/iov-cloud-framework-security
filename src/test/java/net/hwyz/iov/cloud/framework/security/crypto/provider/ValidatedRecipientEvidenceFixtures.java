package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceCertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * 已验证收方证据测试夹具（FW-SEC-DSN-CR-019 两级校验）。
 */
public final class ValidatedRecipientEvidenceFixtures {

    private ValidatedRecipientEvidenceFixtures() {
    }

    /**
     * 标准 P-256 设备证书证据（ECDH-ES 套件）。
     */
    public static ValidatedRecipientEvidence p256Evidence(WrappingSuite suite) throws Exception {
        TestPkiMaterial.Pki pki = TestPkiMaterial.generate();
        return from(pki, "cert-001", suite);
    }

    /**
     * 由给定 PKI 材料构建证据（供解封闭环测试：证据公钥与解封私钥必须同源）。
     */
    public static ValidatedRecipientEvidence p256EvidenceFrom(TestPkiMaterial.Pki pki, String certSerial,
                                                              WrappingSuite suite) throws Exception {
        return from(pki, certSerial, suite);
    }

    /**
     * 无 checked exception 版本（供单元测试便捷使用）。
     */
    public static ValidatedRecipientEvidence evidenceOrThrow(WrappingSuite suite) {
        try {
            return p256Evidence(suite);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 指定曲线 EC 公钥证据（供错误曲线拒绝测试）。
     */
    public static ValidatedRecipientEvidence curveEvidence(String curve, WrappingSuite suite)
            throws Exception {
        KeyPair keyPair = TestPkiMaterial.generateKeyPair(curve);
        byte[] leafDer = TestPkiMaterial.issueEndEntitySelfSigned(
                TestPkiMaterial.LEAF_SUBJECT, keyPair, java.math.BigInteger.valueOf(9),
                -1,
                Instant.now().minusSeconds(3600), Instant.now().plusSeconds(3600 * 24 * 365))
                .getEncoded();
        byte[] spki = keyPair.getPublic().getEncoded();
        return new ValidatedRecipientEvidence("cert-curve", leafDer, spki,
                CanonicalEncoding.hexLower(CanonicalEncoding.sha256(leafDer)),
                DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1, suite,
                Instant.now(), Instant.now().plusSeconds(3600 * 24 * 365),
                ValidatedRecipientEvidence.RecipientStatus.GOOD, "digest", "req-curve");
    }

    /**
     * RSA 公钥证据（RSA-OAEP 套件；leafDer 占位非空即可，wrapper 只使用 SPKI）。
     */
    public static ValidatedRecipientEvidence rsaEvidence(WrappingSuite suite) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        byte[] spki = keyPair.getPublic().getEncoded();
        return new ValidatedRecipientEvidence("cert-rsa", new byte[]{1, 2, 3}, spki,
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                null, suite,
                Instant.now(), Instant.now().plusSeconds(3600 * 24 * 365),
                ValidatedRecipientEvidence.RecipientStatus.GOOD, "digest", "req-rsa");
    }

    private static ValidatedRecipientEvidence from(TestPkiMaterial.Pki pki, String certSerial,
                                                   WrappingSuite suite) throws Exception {
        byte[] leafDer = pki.leafCert().getEncoded();
        byte[] spki = pki.leafKeyPair().getPublic().getEncoded();
        X509Certificate cert = pki.leafCert();
        return new ValidatedRecipientEvidence(certSerial, leafDer, spki,
                CanonicalEncoding.hexLower(CanonicalEncoding.sha256(leafDer)),
                DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1, suite,
                Instant.now(), cert.getNotAfter().toInstant(),
                ValidatedRecipientEvidence.RecipientStatus.GOOD,
                CanonicalEncoding.hexLower(CanonicalEncoding.sha256(leafDer)), "req-1");
    }
}
