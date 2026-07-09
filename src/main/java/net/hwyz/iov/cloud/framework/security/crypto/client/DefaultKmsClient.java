package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;

/**
 * 默认KMS客户端实现
 * 当没有配置KMS端点时使用，调用时会抛出异常
 */
public class DefaultKmsClient implements KmsClient {

    @Override
    public WrappedKey getActiveDataKey(String deviceSn, BizType bizType) {
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

    @Override
    public byte[] hmac(String keyName, byte[] input) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }

    @Override
    public byte[] encryptWith(String keyName, byte[] plaintext) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }

    @Override
    public byte[] decryptWith(String keyName, byte[] ciphertext) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }

    @Override
    public WrappedDataKey wrapActiveDataKeyForDevice(String deviceSn, BizType bizType, String certSerial) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }

    @Override
    public byte[] deriveSessionRoot(String keyName, String vin) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }

    @Override
    public byte[] signWith(String keyName, byte[] data, BizType.SignAlgo algo) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }

    @Override
    public boolean verifyWith(String keyName, byte[] data, byte[] signature, BizType.SignAlgo algo) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }

    @Override
    public byte[] getPublicKey(String keyName) {
        throw new CryptoDependencyUnavailableException("KMS client not configured. Please set crypto.kms.endpoint property.");
    }
}
