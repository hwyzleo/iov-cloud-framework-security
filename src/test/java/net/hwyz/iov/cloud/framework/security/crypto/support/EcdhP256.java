package net.hwyz.iov.cloud.framework.security.crypto.support;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * 测试范围参考密码学原语（FW-SEC-DSN-CR-014 §3.2/§3.3/§3.4）。
 * <p>
 * 独立的 ECDH-ES P-256 + HKDF-SHA-256 + AES-256-GCM 实现，用于<strong>验证</strong>
 * framework 侧 canonical 契约与信封可解封性；<strong>不</strong>作为生产实现。
 * 与生产代码隔离，避免「用被测实现证明被测实现」。
 */
public final class EcdhP256 {

    private static final String EC = "EC";
    private static final String CURVE = "secp256r1";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BYTES = 16;
    private static final int P256_BYTES = 32;
    private static final int POINT_BYTES = 65;

    private static final SecureRandom RANDOM = new SecureRandom();

    private EcdhP256() {
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(EC);
        generator.initialize(new ECGenParameterSpec(CURVE));
        return generator.generateKeyPair();
    }

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    /**
     * 将 P-256 公钥编码为 SEC1 uncompressed（{@code 0x04 || X(32) || Y(32)}，65 字节）。
     */
    public static byte[] encodeUncompressed(ECPublicKey key) {
        byte[] out = new byte[POINT_BYTES];
        out[0] = 0x04;
        System.arraycopy(fixed(key.getW().getAffineX(), P256_BYTES), 0, out, 1, P256_BYTES);
        System.arraycopy(fixed(key.getW().getAffineY(), P256_BYTES), 0, out, 1 + P256_BYTES, P256_BYTES);
        return out;
    }

    /**
     * 从 SEC1 uncompressed 字节还原 P-256 公钥；格式/曲线/点在曲线上均校验（§3.4）。
     */
    public static ECPublicKey decodeUncompressed(byte[] point) {
        if (point == null || point.length != POINT_BYTES || point[0] != 0x04) {
            throw new IllegalArgumentException("server ephemeral public key must be P-256 SEC1 uncompressed (65 bytes)");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 1 + P256_BYTES));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 1 + P256_BYTES, POINT_BYTES));
        try {
            KeyFactory factory = KeyFactory.getInstance(EC);
            ECPublicKey publicKey = (ECPublicKey) factory.generatePublic(
                    new ECPublicKeySpec(new ECPoint(x, y), p256()));
            // 点必须落在曲线上且非无穷点（依赖 JDK 校验 + 显式无穷点检查）。
            if (ECPoint.POINT_INFINITY.equals(publicKey.getW())) {
                throw new IllegalArgumentException("server ephemeral public key must not be the point at infinity");
            }
            return publicKey;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("server ephemeral public key is not on the P-256 curve", e);
        } catch (Exception e) {
            throw new IllegalStateException("failed to decode P-256 public key", e);
        }
    }

    /**
     * ECDH：收方私钥 × 对端公钥 → 共享秘密 Z。
     */
    public static byte[] ecdh(PrivateKey localPrivate, ECPublicKey peerPublic) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(localPrivate);
        agreement.doPhase(peerPublic, true);
        return agreement.generateSecret();
    }

    /**
     * HKDF-SHA-256（RFC 5869）：extract + expand，输出 {@code length} 字节。
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(effectiveSalt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm == null ? new byte[0] : ikm);

        byte[] okm = new byte[length];
        byte[] block = new byte[0];
        int offset = 0;
        int counter = 1;
        while (offset < length) {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(block);
            mac.update(info == null ? new byte[0] : info);
            mac.update((byte) counter);
            block = mac.doFinal();
            int copy = Math.min(block.length, length - offset);
            System.arraycopy(block, 0, okm, offset, copy);
            offset += copy;
            counter++;
        }
        return okm;
    }

    /**
     * AES-256-GCM 加密，返回 {@code ciphertext || tag(16)}（§3.3）。
     */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(plaintext);
    }

    /**
     * AES-256-GCM 解密 {@code ciphertext || tag(16)}；tag 校验失败抛异常（不导入）。
     */
    public static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertextAndTag) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(ciphertextAndTag);
    }

    public static byte[] splitCiphertext(byte[] ciphertextAndTag) {
        return Arrays.copyOf(ciphertextAndTag, ciphertextAndTag.length - GCM_TAG_BYTES);
    }

    public static byte[] splitTag(byte[] ciphertextAndTag) {
        return Arrays.copyOfRange(ciphertextAndTag, ciphertextAndTag.length - GCM_TAG_BYTES,
                ciphertextAndTag.length);
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    public static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data == null ? new byte[0] : data);
    }

    /**
     * KCV = {@code first_3_bytes(SHA-256(businessKey))}（§4）。
     */
    public static byte[] kcvOf(byte[] businessKey) throws Exception {
        return Arrays.copyOf(sha256(businessKey), 3);
    }

    private static ECParameterSpec p256() throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC);
        parameters.init(new ECGenParameterSpec(CURVE));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] fixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        }
        byte[] out = new byte[length];
        if (raw.length > length) {
            System.arraycopy(raw, raw.length - length, out, 0, length);
        } else {
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        }
        return out;
    }
}
