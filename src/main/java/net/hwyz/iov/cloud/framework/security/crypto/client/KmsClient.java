package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;

/**
 * KMS客户端接口
 */
public interface KmsClient {

    /**
     * 获取活跃数据密钥
     *
     * @param deviceSn  设备SN
     * @param bizDomain 业务域
     * @return 包装密钥
     */
    WrappedKey getActiveDataKey(String deviceSn, String bizDomain);

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
}
