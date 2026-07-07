package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;

/**
 * KMS客户端接口
 */
public interface KmsClient {

    /**
     * 获取活跃数据密钥
     *
     * @param deviceSn 设备SN
     * @param bizType  业务类型
     * @return 包装密钥
     */
    WrappedKey getActiveDataKey(String deviceSn, BizType bizType);

    /**
     * 根据keyId获取历史数据密钥
     *
     * @param keyId 密钥ID
     * @return 包装密钥
     */
    WrappedKey getDataKeyById(String keyId);

    /**
     * 解封包装密钥
     *
     * @param wrapped 包装密钥
     * @return 明文DEK
     */
    byte[] unwrap(WrappedKey wrapped);

    /**
     * HMAC派生
     *
     * @param keyName 密钥名称（如oem-master）
     * @param input   输入数据
     * @return HMAC值
     */
    byte[] hmac(String keyName, byte[] input);

    /**
     * 命名密钥封装
     *
     * @param keyName   密钥名称（如KEK）
     * @param plaintext 明文
     * @return 密文
     */
    byte[] encryptWith(String keyName, byte[] plaintext);

    /**
     * 命名密钥解封
     *
     * @param keyName    密钥名称（如KEK）
     * @param ciphertext 密文
     * @return 明文
     */
    byte[] decryptWith(String keyName, byte[] ciphertext);
}
