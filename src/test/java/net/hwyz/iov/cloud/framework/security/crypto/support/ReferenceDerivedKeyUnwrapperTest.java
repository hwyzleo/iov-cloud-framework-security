package net.hwyz.iov.cloud.framework.security.crypto.support;

import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 测试范围参考解封器 / 信封夹具测试（FW-SEC-DSN-CR-014 §3/§4/§10）。
 * <p>
 * 验证：信封自描述可解封、KCV 一致性、同逻辑密钥更换证书时 KCV 不变而 envelopeDigest 改变，
 * 以及篡改临时公钥/salt/nonce/AAD/ciphertext/tag 任一字段即解封失败（不导入）。
 */
class ReferenceDerivedKeyUnwrapperTest {

    @Test
    void sealThenUnwrap_selfDescribingEnvelope_recoversBusinessKey() throws Exception {
        KeyPair recipient = EcdhP256.generateKeyPair();
        byte[] businessKey = EcdhP256.randomBytes(32);
        DerivedEnvelopeFixture.Built built = seal(recipient, businessKey, KeyPurpose.UPLINK_AEAD);

        byte[] recovered = ReferenceDerivedKeyUnwrapper.unwrap(recipient.getPrivate(), built.envelope());

        assertArrayEquals(businessKey, recovered);
        assertArrayEquals(EcdhP256.kcvOf(businessKey), built.envelope().kcv());
    }

    @Test
    void unwrapUplinkAndDownlink_areDomainSeparated() throws Exception {
        KeyPair recipient = EcdhP256.generateKeyPair();
        byte[] businessKey = EcdhP256.randomBytes(32);
        DerivedEnvelopeFixture.Built uplink = seal(recipient, businessKey, KeyPurpose.UPLINK_AEAD);
        DerivedEnvelopeFixture.Built downlink = seal(recipient, businessKey, KeyPurpose.DOWNLINK_AEAD);

        assertArrayEquals(businessKey,
                ReferenceDerivedKeyUnwrapper.unwrap(recipient.getPrivate(), uplink.envelope()));
        assertArrayEquals(businessKey,
                ReferenceDerivedKeyUnwrapper.unwrap(recipient.getPrivate(), downlink.envelope()));
        // 同 VIN/根/版本、不同 purpose → info/AAD 不同 → envelopeDigest 不同（§10）。
        assertFalse(Arrays.equals(uplink.envelope().envelopeDigest(), downlink.envelope().envelopeDigest()));
    }

    @Test
    void sameLogicalKeyChangedCertificate_kcvStable_envelopeDigestChanges() throws Exception {
        byte[] businessKey = EcdhP256.randomBytes(32);
        DerivedEnvelopeFixture.Built first = seal(EcdhP256.generateKeyPair(), businessKey, KeyPurpose.UPLINK_AEAD);
        DerivedEnvelopeFixture.Built rotated = seal(EcdhP256.generateKeyPair(), businessKey, KeyPurpose.UPLINK_AEAD);

        assertArrayEquals(first.envelope().kcv(), rotated.envelope().kcv());
        assertFalse(Arrays.equals(first.envelope().envelopeDigest(), rotated.envelope().envelopeDigest()));
    }

    @Test
    void unwrap_tamperedEphemeralPublicKey_fails() throws Exception {
        assertTamperFails(env -> new DerivedWrappedKeyEnvelopeV1(env.envelopeVersion(), env.wrappingSuite(),
                flip(env.serverEphemeralPublicKey()), env.hkdfSalt(), env.hkdfContextVersion(), env.nonce(),
                env.ciphertext(), env.authenticationTag(), env.aad(), env.aadDigest(),
                env.recipientCertificateFingerprint(), env.logicalKeyId(), env.purpose(),
                env.businessKeyVersion(), env.rootKeyVersion(), env.derivationVersion(), env.kcv(),
                env.operationId(), env.envelopeDigest()));
    }

    @Test
    void unwrap_tamperedSalt_fails() throws Exception {
        assertTamperFails(env -> new DerivedWrappedKeyEnvelopeV1(env.envelopeVersion(), env.wrappingSuite(),
                env.serverEphemeralPublicKey(), flip(env.hkdfSalt()), env.hkdfContextVersion(), env.nonce(),
                env.ciphertext(), env.authenticationTag(), env.aad(), env.aadDigest(),
                env.recipientCertificateFingerprint(), env.logicalKeyId(), env.purpose(),
                env.businessKeyVersion(), env.rootKeyVersion(), env.derivationVersion(), env.kcv(),
                env.operationId(), env.envelopeDigest()));
    }

    @Test
    void unwrap_tamperedNonce_fails() throws Exception {
        assertTamperFails(env -> new DerivedWrappedKeyEnvelopeV1(env.envelopeVersion(), env.wrappingSuite(),
                env.serverEphemeralPublicKey(), env.hkdfSalt(), env.hkdfContextVersion(),
                flip(env.nonce()), env.ciphertext(), env.authenticationTag(), env.aad(), env.aadDigest(),
                env.recipientCertificateFingerprint(), env.logicalKeyId(), env.purpose(),
                env.businessKeyVersion(), env.rootKeyVersion(), env.derivationVersion(), env.kcv(),
                env.operationId(), env.envelopeDigest()));
    }

    @Test
    void unwrap_tamperedAad_fails() throws Exception {
        assertTamperFails(env -> new DerivedWrappedKeyEnvelopeV1(env.envelopeVersion(), env.wrappingSuite(),
                env.serverEphemeralPublicKey(), env.hkdfSalt(), env.hkdfContextVersion(), env.nonce(),
                env.ciphertext(), env.authenticationTag(), flip(env.aad()), env.aadDigest(),
                env.recipientCertificateFingerprint(), env.logicalKeyId(), env.purpose(),
                env.businessKeyVersion(), env.rootKeyVersion(), env.derivationVersion(), env.kcv(),
                env.operationId(), env.envelopeDigest()));
    }

    @Test
    void unwrap_tamperedCiphertext_fails() throws Exception {
        assertTamperFails(env -> new DerivedWrappedKeyEnvelopeV1(env.envelopeVersion(), env.wrappingSuite(),
                env.serverEphemeralPublicKey(), env.hkdfSalt(), env.hkdfContextVersion(), env.nonce(),
                flip(env.ciphertext()), env.authenticationTag(), env.aad(), env.aadDigest(),
                env.recipientCertificateFingerprint(), env.logicalKeyId(), env.purpose(),
                env.businessKeyVersion(), env.rootKeyVersion(), env.derivationVersion(), env.kcv(),
                env.operationId(), env.envelopeDigest()));
    }

    @Test
    void unwrap_tamperedTag_fails() throws Exception {
        assertTamperFails(env -> new DerivedWrappedKeyEnvelopeV1(env.envelopeVersion(), env.wrappingSuite(),
                env.serverEphemeralPublicKey(), env.hkdfSalt(), env.hkdfContextVersion(), env.nonce(),
                env.ciphertext(), flip(env.authenticationTag()), env.aad(), env.aadDigest(),
                env.recipientCertificateFingerprint(), env.logicalKeyId(), env.purpose(),
                env.businessKeyVersion(), env.rootKeyVersion(), env.derivationVersion(), env.kcv(),
                env.operationId(), env.envelopeDigest()));
    }

    @Test
    void decodeUncompressed_rejectsCompressedOrWrongLength() {
        assertThrows(IllegalArgumentException.class,
                () -> EcdhP256.decodeUncompressed(new byte[33]));
        byte[] compressed = new byte[65];
        compressed[0] = 0x02;
        assertThrows(IllegalArgumentException.class, () -> EcdhP256.decodeUncompressed(compressed));
    }

    // ==================== helpers ====================

    private interface EnvelopeMutation {
        DerivedWrappedKeyEnvelopeV1 apply(DerivedWrappedKeyEnvelopeV1 envelope);
    }

    private void assertTamperFails(EnvelopeMutation mutation) throws Exception {
        KeyPair recipient = EcdhP256.generateKeyPair();
        byte[] businessKey = EcdhP256.randomBytes(32);
        DerivedEnvelopeFixture.Built built = seal(recipient, businessKey, KeyPurpose.UPLINK_AEAD);

        // 先确认原始信封可解封，排除夹具本身不可解。
        assertArrayEquals(businessKey,
                ReferenceDerivedKeyUnwrapper.unwrap(recipient.getPrivate(), built.envelope()));

        DerivedWrappedKeyEnvelopeV1 tampered = mutation.apply(built.envelope());
        assertThrows(Exception.class,
                () -> ReferenceDerivedKeyUnwrapper.unwrap(recipient.getPrivate(), tampered));
    }

    private static DerivedEnvelopeFixture.Built seal(KeyPair recipient, byte[] businessKey,
                                                     KeyPurpose purpose) throws Exception {
        return DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) recipient.getPublic(), businessKey, "req-1", "V2C_COMM_ROOT",
                purpose, "logical-v2c-uplink", 7L, 3L, "v1", "ab12cd", "op-1",
                "openbao-derived://ref"));
    }

    private static byte[] flip(byte[] value) {
        byte[] copy = value.clone();
        copy[0] ^= 0x01;
        return copy;
    }
}
