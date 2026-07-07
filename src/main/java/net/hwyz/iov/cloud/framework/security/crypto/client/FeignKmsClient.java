package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;

/**
 * Feign KMS客户端实现
 */
public class FeignKmsClient implements KmsClient {

    private final CryptoProperties properties;
    private final KmsFeignClient kmsFeignClient;

    public FeignKmsClient(CryptoProperties properties, KmsFeignClient kmsFeignClient) {
        this.properties = properties;
        this.kmsFeignClient = kmsFeignClient;
    }

    @Override
    public WrappedKey getActiveDataKey(String deviceSn, BizType bizType) {
        try {
            DataKeyRequest request = new DataKeyRequest();
            request.setDeviceSn(deviceSn);
            request.setBizType(bizType.name());
            WrappedKeyResponse response = kmsFeignClient.getActiveDataKey(request);
            return convertToWrappedKey(response);
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get active data key from KMS", e);
        }
    }

    @Override
    public WrappedKey getDataKeyById(String keyId) {
        try {
            DataKeyByIdRequest request = new DataKeyByIdRequest();
            request.setKeyId(keyId);
            WrappedKeyResponse response = kmsFeignClient.getDataKeyById(request);
            return convertToWrappedKey(response);
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get data key by ID from KMS", e);
        }
    }

    @Override
    public byte[] unwrap(WrappedKey wrapped) {
        try {
            UnwrapRequest request = new UnwrapRequest();
            request.setKeyId(wrapped.getKeyId());
            request.setKeyVersion(wrapped.getKeyVersion());
            request.setWrappedDek(wrapped.getWrappedDek());
            UnwrapResponse response = kmsFeignClient.unwrap(request);
            return response.getDekPlaintext();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to unwrap key from KMS", e);
        }
    }

    @Override
    public byte[] hmac(String keyName, byte[] input) {
        try {
            HmacRequest request = new HmacRequest();
            request.setKeyName(keyName);
            request.setInput(input);
            HmacResponse response = kmsFeignClient.hmac(request);
            return response.getHmac();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to compute HMAC from KMS", e);
        }
    }

    @Override
    public byte[] encryptWith(String keyName, byte[] plaintext) {
        try {
            EncryptWithRequest request = new EncryptWithRequest();
            request.setKeyName(keyName);
            request.setPlaintext(plaintext);
            EncryptWithResponse response = kmsFeignClient.encryptWith(request);
            return response.getCiphertext();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to encrypt with named key from KMS", e);
        }
    }

    @Override
    public byte[] decryptWith(String keyName, byte[] ciphertext) {
        try {
            DecryptWithRequest request = new DecryptWithRequest();
            request.setKeyName(keyName);
            request.setCiphertext(ciphertext);
            DecryptWithResponse response = kmsFeignClient.decryptWith(request);
            return response.getPlaintext();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to decrypt with named key from KMS", e);
        }
    }

    private WrappedKey convertToWrappedKey(WrappedKeyResponse response) {
        WrappedKey wrapped = new WrappedKey();
        wrapped.setKeyId(response.getKeyId());
        wrapped.setKeyVersion(response.getKeyVersion());
        wrapped.setWrappedDek(response.getWrappedDek());
        return wrapped;
    }

    public static class WrappedKeyResponse {
        private String keyId;
        private int keyVersion;
        private byte[] wrappedDek;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public int getKeyVersion() {
            return keyVersion;
        }

        public void setKeyVersion(int keyVersion) {
            this.keyVersion = keyVersion;
        }

        public byte[] getWrappedDek() {
            return wrappedDek;
        }

        public void setWrappedDek(byte[] wrappedDek) {
            this.wrappedDek = wrappedDek;
        }
    }

    public static class DataKeyRequest {
        private String deviceSn;
        private String bizType;

        public String getDeviceSn() {
            return deviceSn;
        }

        public void setDeviceSn(String deviceSn) {
            this.deviceSn = deviceSn;
        }

        public String getBizType() {
            return bizType;
        }

        public void setBizType(String bizType) {
            this.bizType = bizType;
        }
    }

    public static class DataKeyByIdRequest {
        private String keyId;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }
    }

    public static class UnwrapRequest {
        private String keyId;
        private int keyVersion;
        private byte[] wrappedDek;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public int getKeyVersion() {
            return keyVersion;
        }

        public void setKeyVersion(int keyVersion) {
            this.keyVersion = keyVersion;
        }

        public byte[] getWrappedDek() {
            return wrappedDek;
        }

        public void setWrappedDek(byte[] wrappedDek) {
            this.wrappedDek = wrappedDek;
        }
    }

    public static class UnwrapResponse {
        private byte[] dekPlaintext;

        public byte[] getDekPlaintext() {
            return dekPlaintext;
        }

        public void setDekPlaintext(byte[] dekPlaintext) {
            this.dekPlaintext = dekPlaintext;
        }
    }

    public static class HmacRequest {
        private String keyName;
        private byte[] input;

        public String getKeyName() {
            return keyName;
        }

        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }

        public byte[] getInput() {
            return input;
        }

        public void setInput(byte[] input) {
            this.input = input;
        }
    }

    public static class HmacResponse {
        private byte[] hmac;

        public byte[] getHmac() {
            return hmac;
        }

        public void setHmac(byte[] hmac) {
            this.hmac = hmac;
        }
    }

    public static class EncryptWithRequest {
        private String keyName;
        private byte[] plaintext;

        public String getKeyName() {
            return keyName;
        }

        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }

        public byte[] getPlaintext() {
            return plaintext;
        }

        public void setPlaintext(byte[] plaintext) {
            this.plaintext = plaintext;
        }
    }

    public static class EncryptWithResponse {
        private byte[] ciphertext;

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public void setCiphertext(byte[] ciphertext) {
            this.ciphertext = ciphertext;
        }
    }

    public static class DecryptWithRequest {
        private String keyName;
        private byte[] ciphertext;

        public String getKeyName() {
            return keyName;
        }

        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public void setCiphertext(byte[] ciphertext) {
            this.ciphertext = ciphertext;
        }
    }

    public static class DecryptWithResponse {
        private byte[] plaintext;

        public byte[] getPlaintext() {
            return plaintext;
        }

        public void setPlaintext(byte[] plaintext) {
            this.plaintext = plaintext;
        }
    }
}
