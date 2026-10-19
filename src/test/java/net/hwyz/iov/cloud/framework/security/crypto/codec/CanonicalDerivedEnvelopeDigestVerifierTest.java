package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.exception.DerivedEnvelopeIntegrityException;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeView;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.support.DerivedEnvelopeFixture;
import net.hwyz.iov.cloud.framework.security.crypto.support.EcdhP256;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.security.interfaces.ECPublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 公开 canonical envelope digest verifier 测试（FW-SEC-DSN-CR-015 §4.3/§7/§9）。
 * <p>
 * 验证：公开 API 只接受 {@link DerivedWrappedKeyEnvelopeView}（不要求私有 envelope 类型）、
 * 接受结构化视图、拒绝摘要错配（抛 {@link DerivedEnvelopeIntegrityException} 而非返回布尔值）、
 * 冻结向量自检通过，以及异常为确定性、不可重试。
 */
class CanonicalDerivedEnvelopeDigestVerifierTest {

    private static final WrappingSuite SUITE = WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM;
    private static final String FINGERPRINT =
            "ab12cd000000000000000000000000000000000000000000000000000000beef";

    private final CanonicalDerivedEnvelopeDigestVerifier verifier = new CanonicalDerivedEnvelopeDigestVerifier();

    @Test
    void verify_acceptsViewProjectedFromCanonicalEnvelope() throws Exception {
        EcdhEsP256EnvelopeViewV1 view = fixtureView();

        assertDoesNotThrow(() -> verifier.verify(view));
        assertDoesNotThrow(() -> CanonicalDerivedEnvelopeDigestVerifier.verifyView(view));
        assertDoesNotThrow(() -> CanonicalDerivedEnvelopeDigestVerifier.instance().verify(view));
    }

    @Test
    void verify_rejectsTamperedDigest() throws Exception {
        EcdhEsP256EnvelopeViewV1 view = fixtureView();
        byte[] tampered = view.envelopeDigest();
        tampered[0] ^= 0x01;

        EcdhEsP256EnvelopeViewV1 bad = copyWithDigest(view, tampered);

        DerivedEnvelopeIntegrityException ex = assertThrows(DerivedEnvelopeIntegrityException.class,
                () -> verifier.verify(bad));
        assertFalse(ex.isRetryable(), "摘要不匹配为确定性失败，不可重试（CR-015 §4.3）");
        assertEquals(net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException.Reason
                .INTEGRITY_VERIFICATION_FAILED, ex.getReason());
    }

    @Test
    void verify_rejectsNullView() {
        assertThrows(NullPointerException.class, () -> verifier.verify(null));
    }

    @Test
    void publicApi_signatureTakesOnlyPublicView() throws Exception {
        Method verify = net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedEnvelopeDigestVerifier.class
                .getMethod("verify", DerivedWrappedKeyEnvelopeView.class);

        assertEquals(void.class, verify.getReturnType(), "API 不得返回布尔值后由调用方忽略");
        assertEquals(DerivedWrappedKeyEnvelopeView.class, verify.getParameterTypes()[0]);
        // 不得接受私有 envelope 类型
        assertThrows(NoSuchMethodException.class, () -> net.hwyz.iov.cloud.framework.security.crypto.codec
                .DerivedEnvelopeDigestVerifier.class.getMethod("verify",
                        net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1.class));
    }

    @Test
    void selfCheck_passesFrozenVector() {
        assertTrue(CanonicalDerivedEnvelopeDigestVerifier.selfCheck());
    }

    // ==================== helpers ====================

    private static EcdhEsP256EnvelopeViewV1 fixtureView() throws Exception {
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) EcdhP256.generateKeyPair().getPublic(), EcdhP256.randomBytes(32),
                "req-1", "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 7L, 3L, "v1",
                FINGERPRINT, "op-1", "openbao-derived://ref"));
        return DerivedEnvelopeViewFactory.toEcdhEsP256View(built.envelope());
    }

    private static EcdhEsP256EnvelopeViewV1 copyWithDigest(EcdhEsP256EnvelopeViewV1 view,
                                                           byte[] envelopeDigest) {
        return new EcdhEsP256EnvelopeViewV1(
                view.formatVersion(), view.wrappingSuite(), view.serverEphemeralPublicKey(),
                view.hkdfSalt(), view.hkdfContextVersion(), view.nonce(), view.ciphertext(),
                view.authenticationTag(), view.canonicalAad(), view.aadDigest(),
                view.recipientCertificateDigest(), view.logicalKeyId(), view.purpose(),
                view.businessKeyVersion(), view.rootKeyVersion(), view.derivationVersion(),
                view.operationId(), envelopeDigest, view.keyCheckValue());
    }
}
