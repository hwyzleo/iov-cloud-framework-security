package net.hwyz.iov.cloud.framework.security.crypto;

/**
 * 加解密门面API接口
 */
public interface CryptoTemplate {

    /**
     * 加密
     *
     * @param vin       VIN
     * @param bizDomain 业务域
     * @param plaintext 明文
     * @return 密文payload（包含信封头）
     */
    byte[] encrypt(String vin, String bizDomain, byte[] plaintext);

    /**
     * 解密
     *
     * @param cipherPayload 密文payload（包含信封头）
     * @return 明文
     */
    byte[] decrypt(byte[] cipherPayload);
}
