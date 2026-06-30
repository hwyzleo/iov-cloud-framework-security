package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;

/**
 * 默认KMS客户端实现
 * 当没有配置KMS端点时使用，调用时会抛出异常
 */
public class DefaultKmsClient implements KmsClient {

    @Override
    public WrappedKey getActiveDataKey(String deviceSn, String bizDomain) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }

    @Override
    public WrappedKey getDataKeyById(String keyId) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }

    @Override
    public byte[] unwrap(WrappedKey wrapped) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }
}
