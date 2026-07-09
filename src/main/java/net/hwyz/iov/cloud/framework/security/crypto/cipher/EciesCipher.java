package net.hwyz.iov.cloud.framework.security.crypto.cipher;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.kdf.SessionKdf;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData.EncAlg;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

/**
 * ECIES 混合加密工具（ECDH-ES + HKDF-SHA256 + AES-256-GCM）
 * <p>
 * 加密流程：
 * <ol>
 *   <li>生成临时 EC 密钥对（P-256）</li>
 *   <li>ECDH 临时私钥 × 收方公钥 -> 共享秘密 Z</li>
 *   <li>HKDF-SHA256(Z, salt, info) -> 32 字节对称密钥</li>
 *   <li>AES-256-GCM 加密明文</li>
 * </ol>
 * 产物：{@link EnvelopedData}（alg=ECIES_AES_256_GCM，ephemeralPubOrParams=临时公钥 SPKI DER）。
 * <p>
 * 密钥封装（wrapKey）：只做 ECDH-ES + HKDF -> 返回 wrappedKey（共享密钥），不含密文。
 */
public class EciesCipher {

    private static final String EC_ALGORITHM = "EC";
    private static final String EC_CURVE = "secp256r1";
    private static final String ECDH_ALGORITHM = "ECDH";
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
     * @return EnvelopedData（alg=ECIES_AES_256_GCM）
     */
    public EnvelopedData encrypt(byte[] recipientPubKey, byte[] plaintext) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(recipientPubKey);
            PublicKey recipientPublicKey = keyFactory.generatePublic(pubKeySpec);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM);
            kpg.initialize(256);
            KeyPair ephemeralKp = kpg.generateKeyPair();

            KeyAgreement ka = KeyAgreement.getInstance(ECDH_ALGORITHM);
            ka.init(ephemeralKp.getPrivate());
            ka.doPhase(recipientPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);
            byte[] info = SessionKdf.buildInfo("ecies");
            byte[] symmetricKey = SessionKdf.deriveSessionKey(sharedSecret, salt, info);

            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] ephemeralPubSpki = ephemeralKp.getPublic().getEncoded();

            return new EnvelopedData(ciphertext, symmetricKey, EncAlg.ECIES_AES_256_GCM, ephemeralPubSpki);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                    "ECIES encryption failed", e) {};
        }
    }

    /**
     * 密钥封装（key transport）：ECDH-ES + HKDF -> 返回共享密钥
     *
     * @param recipientPubKey 收方公钥 SPKI DER
     * @return 封装的对称密钥（32 字节）
     */
    public byte[] wrapKey(byte[] recipientPubKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(recipientPubKey);
            PublicKey recipientPublicKey = keyFactory.generatePublic(pubKeySpec);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM);
            kpg.initialize(256);
            KeyPair ephemeralKp = kpg.generateKeyPair();

            KeyAgreement ka = KeyAgreement.getInstance(ECDH_ALGORITHM);
            ka.init(ephemeralKp.getPrivate());
            ka.doPhase(recipientPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);
            byte[] info = SessionKdf.buildInfo("ecies-wrap");
            return SessionKdf.deriveSessionKey(sharedSecret, salt, info);
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                    "ECIES key wrap failed", e) {};
        }
    }
}
