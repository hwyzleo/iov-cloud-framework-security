package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Feign KMS客户端实现
 */
@Component
public class FeignKmsClient implements KmsClient {

    private final CryptoProperties properties;
    private final KmsFeignClient kmsFeignClient;

    public FeignKmsClient(CryptoProperties properties, KmsFeignClient kmsFeignClient) {
        this.properties = properties;
        this.kmsFeignClient = kmsFeignClient;
    }

    @Override
    public WrappedKey getActiveDataKey(String deviceSn, String bizDomain) {
        try {
            DataKeyRequest request = new DataKeyRequest();
            request.setDeviceSn(deviceSn);
            request.setBizDomain(bizDomain);
            return kmsFeignClient.getActiveDataKey(request);
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get active data key from KMS", e);
        }
    }

    @Override
    public WrappedKey getDataKeyById(String keyId) {
        try {
            DataKeyByIdRequest request = new DataKeyByIdRequest();
            request.setKeyId(keyId);
            return kmsFeignClient.getDataKeyById(request);
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

    @FeignClient(name = "kms-service", url = "${crypto.kms.endpoint}")
    public interface KmsFeignClient {

        @PostMapping("/transit/datakey")
        WrappedKey getActiveDataKey(@RequestBody DataKeyRequest request);

        @PostMapping("/transit/datakey/by-id")
        WrappedKey getDataKeyById(@RequestBody DataKeyByIdRequest request);

        @PostMapping("/transit/decrypt")
        UnwrapResponse unwrap(@RequestBody UnwrapRequest request);
    }

    public static class DataKeyRequest {
        private String deviceSn;
        private String bizDomain;

        public String getDeviceSn() {
            return deviceSn;
        }

        public void setDeviceSn(String deviceSn) {
            this.deviceSn = deviceSn;
        }

        public String getBizDomain() {
            return bizDomain;
        }

        public void setBizDomain(String bizDomain) {
            this.bizDomain = bizDomain;
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
}
