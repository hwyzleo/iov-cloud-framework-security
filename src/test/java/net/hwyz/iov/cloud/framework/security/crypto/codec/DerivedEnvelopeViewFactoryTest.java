package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.support.DerivedEnvelopeFixture;
import net.hwyz.iov.cloud.framework.security.crypto.support.EcdhP256;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 信封结构化视图工厂测试（FW-SEC-DSN-CR-015 §4.1/§5）。
 * <p>
 * 验证：canonical 信封 → 结构化视图的字段无损投影、证书指纹还原为 32 字节摘要、
 * 投影确定性，以及非 ECDH-ES / 非法指纹 / null 输入的 fail-closed。
 */
class DerivedEnvelopeViewFactoryTest {

    private static final WrappingSuite SUITE = WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM;
    private static final String FINGERPRINT =
            "ab12cd000000000000000000000000000000000000000000000000000000beef";

    @Test
    void projectsCanonicalEnvelopeWithoutLoss() throws Exception {
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) EcdhP256.generateKeyPair().getPublic(), EcdhP256.randomBytes(32),
                "req-1", "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 7L, 3L, "v1",
                FINGERPRINT, "op-1", "openbao-derived://ref"));
        DerivedWrappedKeyEnvelopeV1 envelope = built.envelope();

        EcdhEsP256EnvelopeViewV1 view = DerivedEnvelopeViewFactory.toEcdhEsP256View(envelope);

        assertEquals("ECDH_ES_P256_V1", view.envelopeFormat());
        assertEquals(1, view.formatVersion());
        assertEquals(SUITE, view.wrappingSuite());
        assertArrayEquals(envelope.serverEphemeralPublicKey(), view.serverEphemeralPublicKey());
        assertArrayEquals(envelope.hkdfSalt(), view.hkdfSalt());
        assertEquals(envelope.hkdfContextVersion(), view.hkdfContextVersion());
        assertArrayEquals(envelope.nonce(), view.nonce());
        assertArrayEquals(envelope.ciphertext(), view.ciphertext(), "wrapped_key 必须等于 ciphertext");
        assertArrayEquals(envelope.authenticationTag(), view.authenticationTag());
        assertArrayEquals(envelope.aad(), view.canonicalAad());
        assertArrayEquals(envelope.aadDigest(), view.aadDigest());
        assertArrayEquals(envelope.envelopeDigest(), view.envelopeDigest());
        assertArrayEquals(envelope.kcv(), view.keyCheckValue());
        assertEquals(envelope.logicalKeyId(), view.logicalKeyId());
        assertEquals(envelope.purpose(), view.purpose());
        assertEquals(envelope.businessKeyVersion(), view.businessKeyVersion());
        assertEquals(envelope.rootKeyVersion(), view.rootKeyVersion());
        assertEquals(envelope.derivationVersion(), view.derivationVersion());
        assertEquals(envelope.operationId(), view.operationId());
    }

    @Test
    void recipientCertificateDigest_decodesHexFingerprint() throws Exception {
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) EcdhP256.generateKeyPair().getPublic(), EcdhP256.randomBytes(32),
                "req-1", "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 1L, 1L, "v1",
                FINGERPRINT, "op-1", "openbao-derived://ref"));

        EcdhEsP256EnvelopeViewV1 view = DerivedEnvelopeViewFactory.toEcdhEsP256View(built.envelope());

        assertArrayEquals(CanonicalEncoding.hexDecode(FINGERPRINT), view.recipientCertificateDigest());
        assertEquals(32, view.recipientCertificateDigest().length);
    }

    @Test
    void projection_isDeterministic() throws Exception {
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) EcdhP256.generateKeyPair().getPublic(), EcdhP256.randomBytes(32),
                "req-1", "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 7L, 3L, "v1",
                FINGERPRINT, "op-1", "openbao-derived://ref"));

        EcdhEsP256EnvelopeViewV1 first = DerivedEnvelopeViewFactory.toEcdhEsP256View(built.envelope());
        EcdhEsP256EnvelopeViewV1 second = DerivedEnvelopeViewFactory.toEcdhEsP256View(built.envelope());

        assertEquals(first, second);
        assertTrue(Arrays.equals(first.ciphertext(), second.ciphertext()));
    }

    @Test
    void rejectsNullEnvelope() {
        assertThrows(NullPointerException.class, () -> DerivedEnvelopeViewFactory.toEcdhEsP256View(null));
    }

    @Test
    void rejectsNonEcdhSuite() {
        DerivedWrappedKeyEnvelopeV1 rsa = new DerivedWrappedKeyEnvelopeV1(
                DerivedWrappedKeyEnvelopeV1.V1, WrappingSuite.RSA_OAEP_SHA256, new byte[65],
                new byte[32], DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1, new byte[12], new byte[16],
                new byte[16], new byte[8], new byte[32], FINGERPRINT, "logical-1",
                KeyPurpose.UPLINK_AEAD, 1L, 1L, "v1", new byte[3], "op-1", new byte[32]);

        assertThrows(IllegalArgumentException.class,
                () -> DerivedEnvelopeViewFactory.toEcdhEsP256View(rsa));
    }

    @Test
    void rejectsMissingOrMalformedFingerprint() throws Exception {
        DerivedWrappedKeyEnvelopeV1 blank = withFingerprint(null);
        DerivedWrappedKeyEnvelopeV1 nonHex = withFingerprint("zzzz");
        DerivedWrappedKeyEnvelopeV1 shortDigest = withFingerprint("ab12cd");

        assertThrows(IllegalArgumentException.class,
                () -> DerivedEnvelopeViewFactory.toEcdhEsP256View(blank));
        assertThrows(IllegalArgumentException.class,
                () -> DerivedEnvelopeViewFactory.toEcdhEsP256View(nonHex));
        assertThrows(IllegalArgumentException.class,
                () -> DerivedEnvelopeViewFactory.toEcdhEsP256View(shortDigest));
    }

    @Test
    void hexDecode_supportsPrefixAndCase() {
        assertArrayEquals(new byte[]{0x0a, 0x0b, 0x0c}, CanonicalEncoding.hexDecode("0x0A0B0C"));
        assertArrayEquals(new byte[]{0x0a, 0x0b, 0x0c}, CanonicalEncoding.hexDecode("0A0b0C"));
        assertNull(CanonicalEncoding.hexDecode(null));
        assertArrayEquals(new byte[0], CanonicalEncoding.hexDecode(""));
        assertThrows(IllegalArgumentException.class, () -> CanonicalEncoding.hexDecode("abc"));
    }

    private static DerivedWrappedKeyEnvelopeV1 withFingerprint(String fingerprint) throws Exception {
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) EcdhP256.generateKeyPair().getPublic(), EcdhP256.randomBytes(32),
                "req-1", "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 1L, 1L, "v1",
                FINGERPRINT, "op-1", "openbao-derived://ref"));
        DerivedWrappedKeyEnvelopeV1 envelope = built.envelope();
        return new DerivedWrappedKeyEnvelopeV1(envelope.envelopeVersion(), envelope.wrappingSuite(),
                envelope.serverEphemeralPublicKey(), envelope.hkdfSalt(), envelope.hkdfContextVersion(),
                envelope.nonce(), envelope.ciphertext(), envelope.authenticationTag(), envelope.aad(),
                envelope.aadDigest(), fingerprint, envelope.logicalKeyId(), envelope.purpose(),
                envelope.businessKeyVersion(), envelope.rootKeyVersion(), envelope.derivationVersion(),
                envelope.kcv(), envelope.operationId(), envelope.envelopeDigest());
    }
}
