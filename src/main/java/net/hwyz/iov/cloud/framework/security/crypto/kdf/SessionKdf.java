package net.hwyz.iov.cloud.framework.security.crypto.kdf;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * SESSION 会话根密钥派生工具（HKDF-SHA256）
 * <p>
 * 通用密码学互通契约：
 * <ul>
 *   <li>KDF: HKDF-SHA256</li>
 *   <li>salt / info 约定 + nonce 随密文头自描述（不加密）</li>
 *   <li>AEAD: AES-256-GCM，密文头作 AAD</li>
 * </ul>
 * 该契约通用、与业务无关，是云端 CryptoTemplate SESSION 加解密与车端 SE 实现互通的唯一依据。
 */
public final class SessionKdf {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String SHA_ALGORITHM = "SHA-256";
    private static final int HASH_LENGTH = 32;
    private static final int SESSION_KEY_LENGTH = 32;

    public static final byte MODE_ENVELOPE = 0;
    public static final byte MODE_SESSION = 1;

    public static final String SESSION_INFO_PREFIX = "iov-session:";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SessionKdf() {
    }

    /**
     * HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
     */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(salt, HMAC_ALGORITHM));
            return mac.doFinal(ikm);
        } catch (Exception e) {
            throw new IllegalStateException("HKDF-Extract failed", e);
        }
    }

    /**
     * HKDF-Expand: OKM = HMAC-SHA256(PRK, info | 0x01)
     * <p>
     * 输出 32 字节（AES-256 会话密钥）。
     */
    public static byte[] expand(byte[] prk, byte[] info) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(prk, HMAC_ALGORITHM));
            mac.update(info);
            mac.update((byte) 0x01);
            byte[] okm = mac.doFinal();
            return java.util.Arrays.copyOf(okm, SESSION_KEY_LENGTH);
        } catch (Exception e) {
            throw new IllegalStateException("HKDF-Expand failed", e);
        }
    }

    /**
     * HKDF-SHA256: extract + expand -> 会话密钥
     *
     * @param root 派生根（来自 KMS）
     * @param salt HKDF salt（随密文头自描述）
     * @param info HKDF info
     * @return 32 字节会话密钥
     */
    public static byte[] deriveSessionKey(byte[] root, byte[] salt, byte[] info) {
        byte[] prk = extract(salt, root);
        return expand(prk, info);
    }

    /**
     * 生成随机 salt（16 字节）
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * 构造 SESSION info 字节串
     * <p>
     * 格式: {@code "iov-session:" + bizTypeName}
     *
     * @param bizTypeName BizType 枚举名
     * @return info 字节串
     */
    public static byte[] buildInfo(String bizTypeName) {
        return (SESSION_INFO_PREFIX + bizTypeName).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 计算 SHA-256 摘要的前 4 字节作为 KCV
     */
    public static byte[] computeKcv(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_ALGORITHM);
            byte[] hash = digest.digest(data);
            return java.util.Arrays.copyOf(hash, 4);
        } catch (Exception e) {
            throw new IllegalStateException("KCV computation failed", e);
        }
    }

    static int getHashLength() {
        return HASH_LENGTH;
    }
}
