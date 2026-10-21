package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyEnvelopeCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.support.ReferenceDerivedKeyUnwrapper;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 本地设备证书公钥封装器测试（FW-SEC-DSN-CR-019 §6）。
 * <p>
 * EC P-256 信封须可由 {@link ReferenceDerivedKeyUnwrapper}（模拟 TBOX SEC/HSM）解封并
 * 通过 AAD digest / envelope digest / AEAD tag / KCV 全部校验；RSA-OAEP-SHA256 用私钥解封成功；
 * 错误曲线/非法输入 fail-closed。
 */
class CertificatePublicKeyWrapperTest {

    private final CertificatePublicKeyWrapper wrapper = new CertificatePublicKeyWrapper();

    private WrapEnvelopeContext context(String fingerprint) {
        return new WrapEnvelopeContext("req-1", "V2C_COMM_ROOT", "logical-1", 7L, 3L,
                "v1", "op-1", KeyPurpose.UPLINK_AEAD, fingerprint);
    }

    @Test
    void ecdhP256_roundTrip_unwrapsWithReferenceAndKcvMatches() throws Exception {
        TestPkiMaterial.Pki pki = TestPkiMaterial.generate();
        byte[] keyMaterial = new byte[32];
        for (int i = 0; i < 32; i++) {
            keyMaterial[i] = (byte) i;
        }
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256EvidenceFrom(
                pki, "cert-001", WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);

        DerivedWrappedKeyEnvelopeV1 envelope = wrapper.wrap(keyMaterial, evidence,
                context(evidence.sha256Fingerprint()));

        // 信封自描述：模拟 TBOX SEC/HSM 仅凭信封解封（证据公钥与解封私钥同源）
        byte[] unwrapped = ReferenceDerivedKeyUnwrapper.unwrap(pki.leafKeyPair().getPrivate(), envelope);
        assertArrayEquals(keyMaterial, unwrapped);
        // KCV 与解封材料一致
        assertArrayEquals(net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyKcv
                        .first3Sha256(keyMaterial), envelope.kcv());
        // canonical 摘要自洽
        assertTrue(DerivedKeyEnvelopeCanonical.verifyAadDigest(envelope));
        assertTrue(DerivedKeyEnvelopeCanonical.verifyEnvelopeDigest(envelope));
        // 临时公钥格式：0x04 || X(32) || Y(32)，共 65 字节
        assertEquals(65, envelope.serverEphemeralPublicKey().length);
        assertEquals(0x04, envelope.serverEphemeralPublicKey()[0]);
        assertEquals(32, envelope.hkdfSalt().length);
        assertEquals(12, envelope.nonce().length);
        assertEquals(16, envelope.authenticationTag().length);
    }

    @Test
    void ecdhP256_randomizedWrap_sameKeyDifferentEnvelopeButSameKcv() throws Exception {
        TestPkiMaterial.Pki pki = TestPkiMaterial.generate();
        byte[] keyMaterial = new byte[32];
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256EvidenceFrom(
                pki, "cert-001", WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);

        DerivedWrappedKeyEnvelopeV1 e1 = wrapper.wrap(keyMaterial, evidence,
                context(evidence.sha256Fingerprint()));
        DerivedWrappedKeyEnvelopeV1 e2 = wrapper.wrap(keyMaterial, evidence,
                context(evidence.sha256Fingerprint()));

        // 随机化 Wrap：ciphertext/临时公钥 MAY 不同，但解封结果与 KCV 必须一致
        assertArrayEquals(e1.kcv(), e2.kcv());
        assertArrayEquals(keyMaterial,
                ReferenceDerivedKeyUnwrapper.unwrap(pki.leafKeyPair().getPrivate(), e1));
        assertArrayEquals(keyMaterial,
                ReferenceDerivedKeyUnwrapper.unwrap(pki.leafKeyPair().getPrivate(), e2));
    }

    @Test
    void rsaOaepSha256_unwrapSucceeds() throws Exception {
        var kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        var kp = kpg.generateKeyPair();
        PublicKey rsaPub = kp.getPublic();
        byte[] spki = rsaPub.getEncoded();
        byte[] keyMaterial = new byte[32];
        java.util.Arrays.fill(keyMaterial, (byte) 7);
        ValidatedRecipientEvidence evidence = new ValidatedRecipientEvidence(
                "cert-rsa", new byte[]{1}, spki,
                "aa".repeat(32), null, WrappingSuite.RSA_OAEP_SHA256,
                java.time.Instant.now(), java.time.Instant.now().plusSeconds(3600),
                ValidatedRecipientEvidence.RecipientStatus.GOOD, "d", "req");

        DerivedWrappedKeyEnvelopeV1 envelope = wrapper.wrap(keyMaterial, evidence, context("aa".repeat(32)));

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate(),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] unwrapped = cipher.doFinal(envelope.ciphertext());
        assertArrayEquals(keyMaterial, unwrapped);
        assertEquals(WrappingSuite.RSA_OAEP_SHA256, envelope.wrappingSuite());
        // RSA 无 ECDH 字段（旧格式读取路径：无结构化 view）
        assertNull(envelope.serverEphemeralPublicKey());
        assertTrue(DerivedKeyEnvelopeCanonical.verifyEnvelopeDigest(envelope));
    }

    @Test
    void wrongCurve_rejected() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.curveEvidence(
                "secp384r1", WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        TransitException ex = assertThrows(TransitException.class,
                () -> wrapper.wrap(new byte[32], evidence, context("aa".repeat(32))));
        assertEquals(net.hwyz.iov.cloud.framework.security.crypto.exception.TransitReason.RECIPIENT_CERTIFICATE_INVALID,
                ex.transitReason());
    }

    @Test
    void unsupportedSuite_rejected() {
        assertThrows(TransitException.class, () -> wrapper.wrap(new byte[32],
                ValidatedRecipientEvidenceFixtures.p256Evidence(WrappingSuite.RSA_OAEP_SHA256),
                context("aa".repeat(32))));
    }

    @Test
    void nullInputs_failFast() {
        ValidatedRecipientEvidence evidence;
        try {
            evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                    WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        assertThrows(NullPointerException.class, () -> wrapper.wrap(null, evidence, context("aa".repeat(32))));
        assertThrows(NullPointerException.class, () -> wrapper.wrap(new byte[32], null, context("aa".repeat(32))));
        assertThrows(NullPointerException.class, () -> wrapper.wrap(new byte[32], evidence, null));
    }
}
