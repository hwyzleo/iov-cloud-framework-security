package net.hwyz.iov.cloud.framework.security.crypto.cipher;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData.EncAlg;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA-OAEP 混合加密工具（RSA-OAEP(SHA-256) + AES-256-GCM）
 * <p>
 * 加密流程：
 * <ol>
 *   <li>生成临时 32 字节对称密钥</li>
 *   <li>AES-256-GCM 加密明文</li>
 *   <li>RSA-OAEP(SHA-256) 封装对称密钥</li>
 * </ol>
 * 产物：{@link EnvelopedData}（alg=RSA_OAEP_AES_256_GCM，ephemeralPubOrParams=GCM IV）。
 * <p>
 * 密钥封装（wrapKey）：只做 RSA-OAEP 封装 -> 返回 wrappedKey。
 */
public class RsaOaepCipher {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int KEY_LENGTH = 32;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * 混合加密
     *
     * @param recipientPubKey 收方公钥 SPKI DER
     * @param plaintext       明文
     * @return EnvelopedData（alg=RSA_OAEP_AES_256_GCM）
     */
    public EnvelopedData encrypt(byte[] recipientPubKey, byte[] plaintext) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(recipientPubKey);
            PublicKey recipientPublicKey = keyFactory.generatePublic(pubKeySpec);

            byte[] symmetricKey = new byte[KEY_LENGTH];
            secureRandom.nextBytes(symmetricKey);

            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
            Cipher aesCipher = Cipher.getInstance(AES_TRANSFORMATION);
            aesCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = aesCipher.doFinal(plaintext);

            Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey, oaepParams);
            byte[] wrappedKey = rsaCipher.doFinal(symmetricKey);

            return new EnvelopedData(ciphertext, wrappedKey, EncAlg.RSA_OAEP_AES_256_GCM, iv);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                    "RSA-OAEP encryption failed", e) {};
        }
    }

    /**
     * 密钥封装（key transport）：RSA-OAEP 封装调用方持有的密钥物料
     *
     * @param recipientPubKey 收方公钥 SPKI DER
     * @param keyMaterial     调用方持有的对称密钥/秘密
     * @return RSA-OAEP 封装的密钥密文
     */
    public byte[] wrapKey(byte[] recipientPubKey, byte[] keyMaterial) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(recipientPubKey);
            PublicKey recipientPublicKey = keyFactory.generatePublic(pubKeySpec);

            Cipher rsaCipher = Cipher.getInstance(RSA_TRANSFORMATION);
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey, oaepParams);
            return rsaCipher.doFinal(keyMaterial);
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                    "RSA-OAEP key wrap failed", e) {};
        }
    }
}
