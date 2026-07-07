package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;

/**
 * 加解密门面API接口
 */
public interface CryptoTemplate {

    /**
     * 加密
     *
     * @param vin       VIN
     * @param bizType   业务类型
     * @param plaintext 明文
     * @return 密文payload（包含信封头）
     */
    byte[] encrypt(String vin, BizType bizType, byte[] plaintext);

    /**
     * 解密
     *
     * @param cipherPayload 密文payload（包含信封头）
     * @return 明文
     */
    byte[] decrypt(byte[] cipherPayload);
}
