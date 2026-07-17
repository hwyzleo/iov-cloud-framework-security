package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KdfParams;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedDataKey;
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
    public WrappedKey getActiveDataKey(String keyName, BizType bizType) {
        try {
            DataKeyRequest request = new DataKeyRequest();
            request.setBizType(bizType.name());
            WrappedKeyResponse response = kmsFeignClient.getActiveDataKey(keyName, request);
            return convertToWrappedKey(response);
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get active data key from KMS", e);
        }
    }

    @Override
    public WrappedKey getDataKeyById(String keyName, String keyId) {
        try {
            DataKeyByIdRequest request = new DataKeyByIdRequest();
            request.setKeyId(keyId);
            WrappedKeyResponse response = kmsFeignClient.getDataKeyById(keyName, request);
            return convertToWrappedKey(response);
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get data key by ID from KMS", e);
        }
    }

    @Override
    public byte[] unwrap(String keyName, WrappedKey wrapped) {
        try {
            UnwrapRequest request = new UnwrapRequest();
            request.setKeyId(wrapped.getKeyId());
            request.setKeyVersion(wrapped.getKeyVersion());
            request.setWrappedDek(wrapped.getWrappedDek());
            UnwrapResponse response = kmsFeignClient.unwrap(keyName, request);
            return response.getDekPlaintext();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to unwrap key from KMS", e);
        }
    }

    @Override
    public byte[] hmac(String keyName, byte[] input) {
        try {
            HmacRequest request = new HmacRequest();
            request.setInput(input);
            HmacResponse response = kmsFeignClient.hmac(keyName, request);
            return response.getHmac();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to compute HMAC from KMS", e);
        }
    }

    @Override
    public byte[] encryptWith(String keyName, byte[] plaintext) {
        try {
            EncryptWithRequest request = new EncryptWithRequest();
            request.setPlaintext(plaintext);
            EncryptWithResponse response = kmsFeignClient.encryptWith(keyName, request);
            return response.getCiphertext();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to encrypt with named key from KMS", e);
        }
    }

    @Override
    public byte[] decryptWith(String keyName, byte[] ciphertext) {
        try {
            DecryptWithRequest request = new DecryptWithRequest();
            request.setCiphertext(ciphertext);
            DecryptWithResponse response = kmsFeignClient.decryptWith(keyName, request);
            return response.getPlaintext();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to decrypt with named key from KMS", e);
        }
    }

    @Override
    public WrappedDataKey wrapActiveDataKeyForDevice(String keyName, String deviceSn, BizType bizType, String certSerial) {
        try {
            WrapDataKeyForDeviceRequest request = new WrapDataKeyForDeviceRequest();
            request.setDeviceSn(deviceSn);
            request.setBizType(bizType.name());
            request.setCertSerial(certSerial);
            WrapDataKeyForDeviceResponse response = kmsFeignClient.wrapActiveDataKeyForDevice(request);
            return convertToWrappedDataKey(response);
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to wrap active data key for device from KMS", e);
        }
    }

    @Override
    public byte[] deriveSessionRoot(String keyName, String vin) {
        try {
            SessionRootRequest request = new SessionRootRequest();
            request.setVin(vin);
            SessionRootResponse response = kmsFeignClient.deriveSessionRoot(keyName, request);
            return response.getRoot();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to derive session root from KMS", e);
        }
    }

    @Override
    public byte[] signWith(String keyName, byte[] data, BizType.SignAlgo algo) {
        try {
            SignRequest request = new SignRequest();
            request.setData(data);
            request.setAlgo(algo.name());
            SignResponse response = kmsFeignClient.signWith(keyName, request);
            return response.getSignature();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to sign with KMS", e);
        }
    }

    @Override
    public boolean verifyWith(String keyName, byte[] data, byte[] signature, BizType.SignAlgo algo) {
        try {
            VerifyRequest request = new VerifyRequest();
            request.setData(data);
            request.setSignature(signature);
            request.setAlgo(algo.name());
            VerifyResponse response = kmsFeignClient.verifyWith(keyName, request);
            return response.isValid();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to verify with KMS", e);
        }
    }

    @Override
    public byte[] getPublicKey(String keyName) {
        try {
            PublicKeyRequest request = new PublicKeyRequest();
            PublicKeyResponse response = kmsFeignClient.getPublicKey(keyName, request);
            return response.getPublicKey();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get public key from KMS", e);
        }
    }

    private WrappedKey convertToWrappedKey(WrappedKeyResponse response) {
        WrappedKey wrapped = new WrappedKey();
        wrapped.setKeyId(response.getKeyId());
        wrapped.setKeyVersion(response.getKeyVersion());
        wrapped.setWrappedDek(response.getWrappedDek());
        return wrapped;
    }

    private WrappedDataKey convertToWrappedDataKey(WrapDataKeyForDeviceResponse response) {
        KdfParams kdfParams = null;
        if (response.getKdfSalt() != null) {
            kdfParams = new KdfParams(response.getKdfSalt(),
                    response.getKdfInfo() != null ? response.getKdfInfo() : new byte[0]);
        }
        return new WrappedDataKey(
                response.getWrapped(),
                response.getKeyId(),
                response.getKeyVersion(),
                response.getExpiry() != null ? java.time.Instant.parse(response.getExpiry()) : null,
                kdfParams
        );
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

    public static class WrapDataKeyForDeviceRequest {
        private String deviceSn;
        private String bizType;
        private String certSerial;

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

        public String getCertSerial() {
            return certSerial;
        }

        public void setCertSerial(String certSerial) {
            this.certSerial = certSerial;
        }
    }

    public static class WrapDataKeyForDeviceResponse {
        private byte[] wrapped;
        private String keyId;
        private int keyVersion;
        private String expiry;
        private byte[] kdfSalt;
        private byte[] kdfInfo;

        public byte[] getWrapped() {
            return wrapped;
        }

        public void setWrapped(byte[] wrapped) {
            this.wrapped = wrapped;
        }

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

        public String getExpiry() {
            return expiry;
        }

        public void setExpiry(String expiry) {
            this.expiry = expiry;
        }

        public byte[] getKdfSalt() {
            return kdfSalt;
        }

        public void setKdfSalt(byte[] kdfSalt) {
            this.kdfSalt = kdfSalt;
        }

        public byte[] getKdfInfo() {
            return kdfInfo;
        }

        public void setKdfInfo(byte[] kdfInfo) {
            this.kdfInfo = kdfInfo;
        }
    }

    public static class SessionRootRequest {
        private String keyName;
        private String vin;

        public String getKeyName() {
            return keyName;
        }

        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }

        public String getVin() {
            return vin;
        }

        public void setVin(String vin) {
            this.vin = vin;
        }
    }

    public static class SessionRootResponse {
        private byte[] root;

        public byte[] getRoot() {
            return root;
        }

        public void setRoot(byte[] root) {
            this.root = root;
        }
    }

    public static class SignRequest {
        private String keyName;
        private byte[] data;
        private String algo;

        public String getKeyName() {
            return keyName;
        }

        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }

        public byte[] getData() {
            return data;
        }

        public void setData(byte[] data) {
            this.data = data;
        }

        public String getAlgo() {
            return algo;
        }

        public void setAlgo(String algo) {
            this.algo = algo;
        }
    }

    public static class SignResponse {
        private byte[] signature;

        public byte[] getSignature() {
            return signature;
        }

        public void setSignature(byte[] signature) {
            this.signature = signature;
        }
    }

    public static class VerifyRequest {
        private String keyName;
        private byte[] data;
        private byte[] signature;
        private String algo;

        public String getKeyName() {
            return keyName;
        }

        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }

        public byte[] getData() {
            return data;
        }

        public void setData(byte[] data) {
            this.data = data;
        }

        public byte[] getSignature() {
            return signature;
        }

        public void setSignature(byte[] signature) {
            this.signature = signature;
        }

        public String getAlgo() {
            return algo;
        }

        public void setAlgo(String algo) {
            this.algo = algo;
        }
    }

    public static class VerifyResponse {
        private boolean valid;

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }
    }

    public static class PublicKeyRequest {
        private String keyName;

        public String getKeyName() {
            return keyName;
        }

        public void setKeyName(String keyName) {
            this.keyName = keyName;
        }
    }

    public static class PublicKeyResponse {
        private byte[] publicKey;

        public byte[] getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(byte[] publicKey) {
            this.publicKey = publicKey;
        }
    }
}
