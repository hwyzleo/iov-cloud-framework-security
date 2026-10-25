package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyEnvelopeCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.support.ReferenceDerivedKeyUnwrapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 证书公钥封装器外部 AAD 注入测试（FW-SEC-DSN-CR-020 §3/§7 测试 2）。
 * <p>
 * 验证：加密前注入的 canonical AAD 参与 AES-256-GCM（篡改/替换 AAD 无法解封）、
 * {@code aadDigest = SHA-256(aad)}、AAD 上限 fail-closed、RSA 无 AAD 概念。
 */
class CertificatePublicKeyWrapperAadTest {

    private static final String REQUEST_ID = "req-1";
    private static final String BUSINESS_DOMAIN = "V2C_COMM_ROOT";

    private final CertificatePublicKeyWrapper wrapper = new CertificatePublicKeyWrapper();
    private TestPkiMaterial.Pki pki;
    private ValidatedRecipientEvidence evidence;
    private WrapEnvelopeContext context;

    @BeforeEach
    void setUp() throws Exception {
        pki = TestPkiMaterial.generate();
        evidence = ValidatedRecipientEvidenceFixtures.p256EvidenceFrom(
                pki, "cert-001", WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        context = new WrapEnvelopeContext(REQUEST_ID, BUSINESS_DOMAIN, "logical-1", 7L, 3L,
                "v1", "op-1", KeyPurpose.UPLINK_AEAD, evidence.sha256Fingerprint(),
                net.hwyz.iov.cloud.framework.security.crypto.support
                        .ParProtoKeyprovAadV1Encoder.PROFILE_ID);
    }

    @Test
    void wrapWithAad_externalAadParticipatesInAesGcmAndUnwraps() throws Exception {
        byte[] keyMaterial = new byte[32];
        for (int i = 0; i < 32; i++) {
            keyMaterial[i] = (byte) i;
        }
        byte[] aad = "PAR-PROTO-CANONICAL-AAD|v1".getBytes(StandardCharsets.UTF_8);

        DerivedWrappedKeyEnvelopeV1 envelope = wrapper.wrapWithAad(
                keyMaterial, evidence, context, aad);

        // aadDigest = SHA-256(canonicalAad)；信封 aad 字段 = 注入的同一字节（禁止替换）
        assertArrayEquals(CanonicalEncoding.sha256(aad), envelope.aadDigest());
        assertArrayEquals(aad, envelope.aad());
        // 解封必须使用同一 AAD 才能还原明文（AES-GCM 认证）
        byte[] unwrapped = ReferenceDerivedKeyUnwrapper.unwrapWithInfo(
                pki.leafKeyPair().getPrivate(), envelope, REQUEST_ID, BUSINESS_DOMAIN);
        assertArrayEquals(keyMaterial, unwrapped);
    }

    @Test
    void wrapWithAad_tamperedAad_failsToUnwrap() throws Exception {
        byte[] keyMaterial = new byte[32];
        byte[] aad = "PAR-PROTO-CANONICAL-AAD|v1".getBytes(StandardCharsets.UTF_8);
        DerivedWrappedKeyEnvelopeV1 envelope = wrapper.wrapWithAad(
                keyMaterial, evidence, context, aad);

        // 加密后替换 AAD（如用旧 FW AAD 重算）：tag 校验失败，不可导入
        byte[] tampered = Arrays.copyOf(aad, aad.length);
        tampered[0] ^= 0x01;
        DerivedWrappedKeyEnvelopeV1 replaced = new DerivedWrappedKeyEnvelopeV1(
                DerivedWrappedKeyEnvelopeV1.V1, envelope.wrappingSuite(),
                envelope.serverEphemeralPublicKey(), envelope.hkdfSalt(),
                envelope.hkdfContextVersion(), envelope.nonce(), envelope.ciphertext(),
                envelope.authenticationTag(), tampered, envelope.aadDigest(),
                envelope.recipientCertificateFingerprint(), envelope.logicalKeyId(),
                envelope.purpose(), envelope.businessKeyVersion(), envelope.rootKeyVersion(),
                envelope.derivationVersion(), envelope.kcv(), envelope.operationId(),
                envelope.envelopeDigest());
        assertThrows(IllegalStateException.class,
                () -> ReferenceDerivedKeyUnwrapper.unwrapWithInfo(
                        pki.leafKeyPair().getPrivate(), replaced, REQUEST_ID, BUSINESS_DOMAIN),
                "加密后替换 AAD 必须导致解封失败（禁止用旧 AAD 重算 tag，CR-020 §3）");
    }

    @Test
    void wrapWithAad_rejectsNullEmptyOversizedAad_failClosed() {
        byte[] keyMaterial = new byte[32];
        assertThrows(NullPointerException.class,
                () -> wrapper.wrapWithAad(keyMaterial, evidence, context, null));
        assertThrows(TransitException.class,
                () -> wrapper.wrapWithAad(keyMaterial, evidence, context, new byte[0]));
        assertThrows(TransitException.class,
                () -> wrapper.wrapWithAad(keyMaterial, evidence, context, new byte[2048]),
                "AAD 超过 1 KiB 上限 fail-closed（CR-020 §3）");
    }

    @Test
    void wrapWithAad_rsaSuite_rejectedAadNotApplicable() throws Exception {
        // RSA-OAEP 无 AAD 概念：wrapWithAad 对 RSA 套件 fail-closed
        ValidatedRecipientEvidence rsa = ValidatedRecipientEvidenceFixtures.rsaEvidence(
                WrappingSuite.RSA_OAEP_SHA256);
        assertThrows(TransitException.class,
                () -> wrapper.wrapWithAad(new byte[32], rsa, context,
                        "aad".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void wrap_legacyCoreAadPath_stillUnwrapsWithParsedInfo() throws Exception {
        // legacy 内部 core AAD 路径（无 profile 旧格式）：沿用旧解封路径
        byte[] keyMaterial = new byte[32];
        DerivedWrappedKeyEnvelopeV1 envelope = wrapper.wrap(keyMaterial, evidence,
                new WrapEnvelopeContext(REQUEST_ID, BUSINESS_DOMAIN, "logical-1", 7L, 3L,
                        "v1", "op-1", KeyPurpose.UPLINK_AEAD, evidence.sha256Fingerprint()));
        assertTrue(DerivedKeyEnvelopeCanonical.verifyEnvelopeDigest(envelope));
        byte[] unwrapped = ReferenceDerivedKeyUnwrapper.unwrap(
                pki.leafKeyPair().getPrivate(), envelope);
        assertArrayEquals(keyMaterial, unwrapped);
    }
}
