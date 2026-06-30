package net.hwyz.iov.cloud.framework.security.crypto.cipher;

import net.hwyz.iov.cloud.framework.security.crypto.exception.IntegrityVerificationException;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AEAD加密器（AES-256-GCM）
 */
@Component
public class AeadCipher {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96-bit
    private static final int GCM_TAG_LENGTH = 128; // 128-bit tag

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * 生成随机IV
     *
     * @return IV字节数组
     */
    public byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * 加密
     *
     * @param plaintext 明文
     * @param dek       明文DEK
     * @param iv        初始化向量
     * @param aad       附加认证数据（信封头）
     * @return 密文 + tag
     */
    public byte[] encrypt(byte[] plaintext, byte[] dek, byte[] iv, byte[] aad) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(dek, ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

            if (aad != null) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new IntegrityVerificationException("Encryption failed", e);
        }
    }

    /**
     * 解密
     *
     * @param ciphertext 密文 + tag
     * @param dek        明文DEK
     * @param iv         初始化向量
     * @param aad        附加认证数据（信封头）
     * @return 明文
     */
    public byte[] decrypt(byte[] ciphertext, byte[] dek, byte[] iv, byte[] aad) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(dek, ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

            if (aad != null) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new IntegrityVerificationException("Decryption failed: integrity verification failed", e);
        }
    }
}
