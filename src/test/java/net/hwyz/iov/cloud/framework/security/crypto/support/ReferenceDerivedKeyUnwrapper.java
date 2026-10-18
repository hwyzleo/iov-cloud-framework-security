package net.hwyz.iov.cloud.framework.security.crypto.support;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyEnvelopeCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * 测试范围参考解封器（FW-SEC-DSN-CR-014 §3/§4/§10）。
 * <p>
 * 模拟 TBOX SEC/HSM：<strong>仅凭信封</strong>（含 canonical AAD）独立计算 KEK 并解封，
 * 不依赖 VMD/VAGW 注入隐式密码参数——即验证信封「自描述」。用于 framework canonical
 * 契约与字节级幂等的端到端验证，不作为生产实现。
 * <p>
 * 解封流程：解析 AAD 恢复 {@code info} 上下文 → ECDH(收方私钥, 临时公钥) → HKDF-SHA-256 →
 * AES-256-GCM 校验 tag 并解出业务密钥 → 校验 KCV。
 */
public final class ReferenceDerivedKeyUnwrapper {

    private ReferenceDerivedKeyUnwrapper() {
    }

    /**
     * 解封并校验 AAD digest / envelope digest / AEAD tag / KCV，返回业务密钥明文。
     *
     * @throws IllegalStateException 任一完整性校验失败（视为不可导入）
     */
    public static byte[] unwrap(PrivateKey recipientPrivateKey, DerivedWrappedKeyEnvelopeV1 envelope)
            throws Exception {
        byte[] aad = envelope.aad();
        if (aad == null || !CanonicalEncoding.constantTimeEquals(envelope.aadDigest(),
                CanonicalEncoding.sha256(aad))) {
            throw new IllegalStateException("AAD digest mismatch: envelope rejected");
        }
        if (!DerivedKeyEnvelopeCanonical.verifyEnvelopeDigest(envelope)) {
            throw new IllegalStateException("envelope digest mismatch: envelope rejected");
        }

        String[] fields = decodeAadFields(aad);
        String requestId = fields[2];
        String businessDomain = fields[3];
        String purpose = fields[4];
        String keyId = fields[5];
        long businessKeyVersion = Long.parseLong(fields[6]);
        String fingerprint = fields[9];
        String info = DerivedKeyEnvelopeCanonical.kdfInfo(requestId, businessDomain,
                purpose == null || purpose.isEmpty() ? null : KeyPurpose.valueOf(purpose),
                keyId, businessKeyVersion, fingerprint);

        ECPublicKey ephemeral = EcdhP256.decodeUncompressed(envelope.serverEphemeralPublicKey());
        byte[] shared = EcdhP256.ecdh(recipientPrivateKey, ephemeral);
        byte[] kek = EcdhP256.hkdfSha256(shared, envelope.hkdfSalt(),
                info.getBytes(StandardCharsets.UTF_8), 32);
        byte[] ciphertextAndTag = EcdhP256.concat(envelope.ciphertext(), envelope.authenticationTag());
        byte[] businessKey = EcdhP256.aesGcmDecrypt(kek, envelope.nonce(), aad, ciphertextAndTag);

        byte[] expectedKcv = EcdhP256.kcvOf(businessKey);
        if (!CanonicalEncoding.constantTimeEquals(expectedKcv, envelope.kcv())) {
            throw new IllegalStateException("KCV mismatch: imported key rejected");
        }
        return businessKey;
    }

    /**
     * 解析 canonical AAD 的长度前缀字段（确定性顺序，见 {@code DerivedKeyEnvelopeCanonical#aadBytes}）。
     */
    static String[] decodeAadFields(byte[] aad) {
        String[] fields = new String[10];
        int offset = 0;
        for (int i = 0; i < fields.length; i++) {
            if (offset + 4 > aad.length) {
                throw new IllegalStateException("malformed canonical AAD: truncated length prefix");
            }
            int length = ((aad[offset] & 0xFF) << 24) | ((aad[offset + 1] & 0xFF) << 16)
                    | ((aad[offset + 2] & 0xFF) << 8) | (aad[offset + 3] & 0xFF);
            offset += 4;
            if (length < 0 || offset + length > aad.length) {
                throw new IllegalStateException("malformed canonical AAD: field length out of range");
            }
            fields[i] = new String(Arrays.copyOfRange(aad, offset, offset + length), StandardCharsets.UTF_8);
            offset += length;
        }
        if (offset != aad.length) {
            throw new IllegalStateException("malformed canonical AAD: trailing bytes");
        }
        return fields;
    }
}
