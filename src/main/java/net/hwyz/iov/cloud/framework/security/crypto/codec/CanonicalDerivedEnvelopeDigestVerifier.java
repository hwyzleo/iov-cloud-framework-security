package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.exception.DerivedEnvelopeIntegrityException;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeView;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

import java.util.Objects;

/**
 * {@link DerivedEnvelopeDigestVerifier} 的 canonical 实现（FW-SEC-DSN-CR-015 §4.3）。
 * <p>
 * <strong>只依据公开 view</strong> 重建 CR-014 canonical envelope 输入并复算摘要：先把 view 的
 * 全部 digest-bound 字段映射回内部 {@link DerivedWrappedKeyEnvelopeV1}（私有类型仅作 core 内部
 * 传递，绝不作为公开 API 入参），再复用 {@link DerivedKeyEnvelopeCanonical} 的唯一权威编码器
 * 与恒时比较。canonical 的字段顺序/长度前缀/编码规则不在本类重复定义（RD-015-4）。
 * <p>
 * 视图的 {@code recipientCertificateDigest}（32 字节）按 canonical 规则重新编码为小写十六进制，
 * 与信封的 {@code recipientCertificateFingerprint} 一一对应。
 */
public final class CanonicalDerivedEnvelopeDigestVerifier implements DerivedEnvelopeDigestVerifier {

    private static final CanonicalDerivedEnvelopeDigestVerifier INSTANCE = new CanonicalDerivedEnvelopeDigestVerifier();

    public CanonicalDerivedEnvelopeDigestVerifier() {
    }

    /** 协议无关共享实现的单例句柄。 */
    public static CanonicalDerivedEnvelopeDigestVerifier instance() {
        return INSTANCE;
    }

    /** 便捷入口：等价于 {@code instance().verify(view)}。 */
    public static void verifyView(DerivedWrappedKeyEnvelopeView view) {
        INSTANCE.verify(view);
    }

    @Override
    public void verify(DerivedWrappedKeyEnvelopeView view) {
        Objects.requireNonNull(view, "envelope view must not be null");
        byte[] declared = view.coreEnvelopeDigest();
        if (declared == null || declared.length != EcdhEsP256EnvelopeViewV1.DIGEST_LENGTH) {
            throw new DerivedEnvelopeIntegrityException(
                    "envelope view must carry a " + EcdhEsP256EnvelopeViewV1.DIGEST_LENGTH
                            + "-byte envelopeDigest, got "
                            + (declared == null ? "null" : declared.length + " bytes"));
        }
        byte[] recomputed = DerivedKeyEnvelopeCanonical.envelopeDigest(canonicalEnvelope(view));
        if (!CanonicalEncoding.constantTimeEquals(declared, recomputed)) {
            throw new DerivedEnvelopeIntegrityException(
                    "envelopeDigest mismatch for format=" + view.envelopeFormat()
                            + "/v" + view.formatVersion() + " (FW-SEC-DSN-CR-015 §4.3)");
        }
    }

    /**
     * 按 {@code envelopeFormat + formatVersion} 分派，从公开 view 的全部 digest-bound 字段
     * 重建 canonical envelope 输入（不含 {@code envelopeDigest}）。
     */
    private static DerivedWrappedKeyEnvelopeV1 canonicalEnvelope(DerivedWrappedKeyEnvelopeView view) {
        if (view instanceof EcdhEsP256EnvelopeViewV1 v1
                && EcdhEsP256EnvelopeViewV1.ENVELOPE_FORMAT.equals(v1.envelopeFormat())
                && v1.formatVersion() == EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1) {
            return new DerivedWrappedKeyEnvelopeV1(
                    DerivedWrappedKeyEnvelopeV1.V1, v1.wrappingSuite(),
                    v1.serverEphemeralPublicKey(), v1.hkdfSalt(), v1.hkdfContextVersion(),
                    v1.nonce(), v1.ciphertext(), v1.authenticationTag(), v1.canonicalAad(), v1.aadDigest(),
                    CanonicalEncoding.hexLower(v1.recipientCertificateDigest()),
                    v1.logicalKeyId(), v1.purpose(), v1.businessKeyVersion(), v1.rootKeyVersion(),
                    v1.derivationVersion(), v1.keyCheckValue(), v1.operationId(), null);
        }
        throw new DerivedEnvelopeIntegrityException(
                "unsupported envelope format/version for canonical verify: "
                        + view.envelopeFormat() + "/v" + view.formatVersion());
    }

    /**
     * 运行时门禁自检（FW-SEC-DSN-CR-015 §7）：对冻结向量同时验证「接受正确摘要」与
     * 「拒绝篡改摘要」，并据此判定 {@code CORE_ENVELOPE_DIGEST_VERIFY_V1} 是否 READY。
     *
     * @return 自检通过返回 true；任何异常均视为 false（fail-closed）
     */
    public static boolean selfCheck() {
        try {
            EcdhEsP256EnvelopeViewV1 view = fixedVectorView(probeDigest());
            INSTANCE.verify(view);

            byte[] tampered = probeDigest();
            tampered[0] ^= 0x01;
            try {
                INSTANCE.verify(fixedVectorView(tampered));
                return false;
            } catch (DerivedEnvelopeIntegrityException expected) {
                return true;
            }
        } catch (Throwable t) {
            return false;
        }
    }

    private static byte[] probeDigest() {
        byte[] ephemeral = new byte[65];
        ephemeral[0] = 0x04;
        for (int i = 0; i < 64; i++) {
            ephemeral[1 + i] = (byte) i;
        }
        DerivedWrappedKeyEnvelopeV1 probe = new DerivedWrappedKeyEnvelopeV1(
                DerivedWrappedKeyEnvelopeV1.V1, SUITE, ephemeral, sequence(0x10, 32),
                DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1, sequence(0xA0, 12), sequence(0xB0, 32),
                sequence(0xC0, 16), sequence(0xE0, 8), sequence(0xD0, 32), FINGERPRINT,
                LOGICAL_KEY_ID, KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", KCV, "op-1", null);
        return DerivedKeyEnvelopeCanonical.envelopeDigest(probe);
    }

    private static EcdhEsP256EnvelopeViewV1 fixedVectorView(byte[] envelopeDigest) {
        byte[] ephemeral = new byte[65];
        ephemeral[0] = 0x04;
        for (int i = 0; i < 64; i++) {
            ephemeral[1 + i] = (byte) i;
        }
        return new EcdhEsP256EnvelopeViewV1(
                EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1, SUITE, ephemeral, sequence(0x10, 32),
                DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1, sequence(0xA0, 12), sequence(0xB0, 32),
                sequence(0xC0, 16), sequence(0xE0, 8), sequence(0xD0, 32),
                CanonicalEncoding.hexDecode(FINGERPRINT),
                LOGICAL_KEY_ID, KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", "op-1", envelopeDigest, KCV);
    }

    private static byte[] sequence(int start, int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) ((start + i) & 0xFF);
        }
        return out;
    }

    private static final WrappingSuite SUITE = WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM;
    private static final String LOGICAL_KEY_ID = "logical-v2c-uplink";
    private static final byte[] KCV = {0x0a, 0x0b, 0x0c};
    private static final String FINGERPRINT =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
}
