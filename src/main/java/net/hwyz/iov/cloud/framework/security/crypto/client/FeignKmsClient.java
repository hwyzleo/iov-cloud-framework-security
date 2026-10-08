package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyNotFoundException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KdfParams;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;

import java.time.Instant;
import java.util.Map;

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
            String hmacValue = response.getData().getHmac();
            // OpenBao返回格式: "vault:v1:<base64>"，需要去掉前缀
            if (hmacValue.startsWith("vault:")) {
                int lastColon = hmacValue.lastIndexOf(':');
                if (lastColon > 0) {
                    hmacValue = hmacValue.substring(lastColon + 1);
                }
            }
            return java.util.Base64.getDecoder().decode(hmacValue);
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

    // ==================== 业务密钥材料（FW-SEC-DSN-CR-009 §9） ====================

    @Override
    public KmsKeyMaterial createDataKey(KmsCreateKeyCommand command) {
        try {
            CreateBusinessKeyRequest request = new CreateBusinessKeyRequest();
            request.setBizType(command.bizType());
            request.setAlgorithm(command.algorithm());
            request.setKeySpec(command.keySpec());
            request.setIdempotencyKey(command.idempotencyKey());
            request.setAuditContext(command.auditContext());
            CreateBusinessKeyResponse response = kmsFeignClient.createBusinessKey(request);
            return mapKeyMaterial(response);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw classify(e, "create business key");
        }
    }

    @Override
    public KmsWrappedKey wrapKey(KmsKeyReference keyRef, KmsRecipient recipient) {
        try {
            WrapBusinessKeyRequest request = new WrapBusinessKeyRequest();
            request.setKeyId(keyRef.keyId());
            request.setKmsKeyRef(keyRef.kmsKeyRef());
            request.setMode(recipient.mode().name());
            request.setCertSerial(recipient.certSerial());
            request.setSpki(recipient.spki());
            request.setAudience(recipient.audience());
            request.setWrappingKeyRef(recipient.wrappingKeyRef());
            WrapBusinessKeyResponse response = kmsFeignClient.wrapBusinessKey(request);
            return mapWrappedKey(response);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw classify(e, "wrap business key");
        }
    }

    @Override
    public KmsKeyMetadata getKeyMetadata(KmsKeyReference keyRef) {
        try {
            BusinessKeyMetadataRequest request = new BusinessKeyMetadataRequest();
            request.setKeyId(keyRef.keyId());
            request.setKmsKeyRef(keyRef.kmsKeyRef());
            BusinessKeyMetadataResponse response = kmsFeignClient.getBusinessKeyMetadata(request);
            return mapKeyMetadata(response);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw classify(e, "get business key metadata");
        }
    }

    @Override
    public KmsRevocationResult revokeKey(KmsKeyReference keyRef, String reason, String idempotencyKey) {
        try {
            RevokeBusinessKeyRequest request = new RevokeBusinessKeyRequest();
            request.setKeyId(keyRef.keyId());
            request.setKmsKeyRef(keyRef.kmsKeyRef());
            request.setReason(reason);
            request.setIdempotencyKey(idempotencyKey);
            RevokeBusinessKeyResponse response = kmsFeignClient.revokeBusinessKey(request);
            return new KmsRevocationResult(
                    response.getKeyId(),
                    parseState(response.getState()),
                    response.getChangedAt() != null ? Instant.parse(response.getChangedAt()) : null);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw classify(e, "revoke business key");
        }
    }

    /**
     * 业务密钥材料操作失败分类（FW-SEC-DSN-CR-009 §7/§11）。
     * <p>
     * - 404 → BusinessKeyNotFoundException；
     * - 409 → BusinessKeyIdempotencyConflictException；
     * - 5xx / 超时 / retryable（请求体可能已发送）→ CryptoOperationOutcomeUnknownException（须原幂等键对账）；
     * - 连接拒绝等请求体明确未发送 → CryptoDependencyUnavailableException（可按预算重试）。
     * 精确区分最终由 KMS Provider Adapter 负责，此处为框架兜底分类。
     */
    private CryptoException classify(Exception e, String op) {
        Throwable t = unwrapCause(e);
        if (t instanceof feign.FeignException fe) {
            int status = fe.status();
            if (status == 404) {
                return new BusinessKeyNotFoundException(op + " not found (http 404)", e);
            }
            if (status == 409) {
                return new BusinessKeyIdempotencyConflictException(op + " idempotency conflict (http 409)", e);
            }
            if (status < 0 || status >= 500) {
                return new CryptoOperationOutcomeUnknownException(
                        op + " outcome unknown (http " + status + ")", e);
            }
            return new CryptoDependencyUnavailableException(op + " failed (http " + status + ")", e);
        }
        if (t instanceof java.net.SocketTimeoutException) {
            return new CryptoOperationOutcomeUnknownException(op + " outcome unknown (timeout)", e);
        }
        if (t instanceof java.net.ConnectException) {
            return new CryptoDependencyUnavailableException(op + " unavailable (connect, request not sent)", e);
        }
        if (t instanceof feign.RetryableException) {
            return new CryptoOperationOutcomeUnknownException(op + " outcome unknown (retryable)", e);
        }
        return new CryptoDependencyUnavailableException(op + " failed", e);
    }

    private Throwable unwrapCause(Throwable t) {
        Throwable current = t;
        int depth = 0;
        while (current != null && current.getCause() != null && depth < 6) {
            current = current.getCause();
            depth++;
        }
        return current != null ? current : t;
    }

    private KmsKeyMaterial mapKeyMaterial(CreateBusinessKeyResponse response) {
        return new KmsKeyMaterial(
                response.getKeyId(),
                response.getKmsKeyRef(),
                response.getKmsKeyVersion(),
                response.getProvider(),
                response.getAlgorithm(),
                response.getKeySpec(),
                response.getValidFrom() != null ? Instant.parse(response.getValidFrom()) : null,
                response.getValidTo() != null ? Instant.parse(response.getValidTo()) : null);
    }

    private KmsWrappedKey mapWrappedKey(WrapBusinessKeyResponse response) {
        return new KmsWrappedKey(
                response.getWrapped(),
                response.getKeyId(),
                response.getKmsKeyVersion(),
                response.getAlgorithm(),
                response.getExpiry() != null ? Instant.parse(response.getExpiry()) : null,
                response.getParameters());
    }

    private KmsKeyMetadata mapKeyMetadata(BusinessKeyMetadataResponse response) {
        return new KmsKeyMetadata(
                response.getKeyId(),
                response.getKmsKeyRef(),
                response.getKmsKeyVersion(),
                response.getProvider(),
                response.getAlgorithm(),
                response.getKeySpec(),
                parseState(response.getState()),
                response.getValidFrom() != null ? Instant.parse(response.getValidFrom()) : null,
                response.getValidTo() != null ? Instant.parse(response.getValidTo()) : null,
                response.getDecryptUntil() != null ? Instant.parse(response.getDecryptUntil()) : null);
    }

    private CryptoKeyState parseState(String state) {
        if (state == null) {
            return null;
        }
        try {
            return CryptoKeyState.valueOf(state);
        } catch (IllegalArgumentException e) {
            return null;
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
        private HmacData data;

        public HmacData getData() {
            return data;
        }

        public void setData(HmacData data) {
            this.data = data;
        }

        public static class HmacData {
            private String hmac;

            public String getHmac() {
                return hmac;
            }

            public void setHmac(String hmac) {
                this.hmac = hmac;
            }
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

    // ==================== 业务密钥材料 DTO（FW-SEC-DSN-CR-009 §9） ====================

    public static class CreateBusinessKeyRequest {
        private String bizType;
        private String algorithm;
        private String keySpec;
        private String idempotencyKey;
        private Map<String, String> auditContext;

        public String getBizType() {
            return bizType;
        }

        public void setBizType(String bizType) {
            this.bizType = bizType;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getKeySpec() {
            return keySpec;
        }

        public void setKeySpec(String keySpec) {
            this.keySpec = keySpec;
        }

        public String getIdempotencyKey() {
            return idempotencyKey;
        }

        public void setIdempotencyKey(String idempotencyKey) {
            this.idempotencyKey = idempotencyKey;
        }

        public Map<String, String> getAuditContext() {
            return auditContext;
        }

        public void setAuditContext(Map<String, String> auditContext) {
            this.auditContext = auditContext;
        }
    }

    public static class CreateBusinessKeyResponse {
        private String keyId;
        private String kmsKeyRef;
        private Integer kmsKeyVersion;
        private String provider;
        private String algorithm;
        private String keySpec;
        private String validFrom;
        private String validTo;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getKmsKeyRef() {
            return kmsKeyRef;
        }

        public void setKmsKeyRef(String kmsKeyRef) {
            this.kmsKeyRef = kmsKeyRef;
        }

        public Integer getKmsKeyVersion() {
            return kmsKeyVersion;
        }

        public void setKmsKeyVersion(Integer kmsKeyVersion) {
            this.kmsKeyVersion = kmsKeyVersion;
        }

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getKeySpec() {
            return keySpec;
        }

        public void setKeySpec(String keySpec) {
            this.keySpec = keySpec;
        }

        public String getValidFrom() {
            return validFrom;
        }

        public void setValidFrom(String validFrom) {
            this.validFrom = validFrom;
        }

        public String getValidTo() {
            return validTo;
        }

        public void setValidTo(String validTo) {
            this.validTo = validTo;
        }
    }

    public static class WrapBusinessKeyRequest {
        private String keyId;
        private String kmsKeyRef;
        private String mode;
        private String certSerial;
        private byte[] spki;
        private String audience;
        private String wrappingKeyRef;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getKmsKeyRef() {
            return kmsKeyRef;
        }

        public void setKmsKeyRef(String kmsKeyRef) {
            this.kmsKeyRef = kmsKeyRef;
        }

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }

        public String getCertSerial() {
            return certSerial;
        }

        public void setCertSerial(String certSerial) {
            this.certSerial = certSerial;
        }

        public byte[] getSpki() {
            return spki;
        }

        public void setSpki(byte[] spki) {
            this.spki = spki;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getWrappingKeyRef() {
            return wrappingKeyRef;
        }

        public void setWrappingKeyRef(String wrappingKeyRef) {
            this.wrappingKeyRef = wrappingKeyRef;
        }
    }

    public static class WrapBusinessKeyResponse {
        private byte[] wrapped;
        private String keyId;
        private Integer kmsKeyVersion;
        private String algorithm;
        private String expiry;
        private Map<String, String> parameters;

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

        public Integer getKmsKeyVersion() {
            return kmsKeyVersion;
        }

        public void setKmsKeyVersion(Integer kmsKeyVersion) {
            this.kmsKeyVersion = kmsKeyVersion;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getExpiry() {
            return expiry;
        }

        public void setExpiry(String expiry) {
            this.expiry = expiry;
        }

        public Map<String, String> getParameters() {
            return parameters;
        }

        public void setParameters(Map<String, String> parameters) {
            this.parameters = parameters;
        }
    }

    public static class BusinessKeyMetadataRequest {
        private String keyId;
        private String kmsKeyRef;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getKmsKeyRef() {
            return kmsKeyRef;
        }

        public void setKmsKeyRef(String kmsKeyRef) {
            this.kmsKeyRef = kmsKeyRef;
        }
    }

    public static class BusinessKeyMetadataResponse {
        private String keyId;
        private String kmsKeyRef;
        private Integer kmsKeyVersion;
        private String provider;
        private String algorithm;
        private String keySpec;
        private String state;
        private String validFrom;
        private String validTo;
        private String decryptUntil;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getKmsKeyRef() {
            return kmsKeyRef;
        }

        public void setKmsKeyRef(String kmsKeyRef) {
            this.kmsKeyRef = kmsKeyRef;
        }

        public Integer getKmsKeyVersion() {
            return kmsKeyVersion;
        }

        public void setKmsKeyVersion(Integer kmsKeyVersion) {
            this.kmsKeyVersion = kmsKeyVersion;
        }

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getKeySpec() {
            return keySpec;
        }

        public void setKeySpec(String keySpec) {
            this.keySpec = keySpec;
        }

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getValidFrom() {
            return validFrom;
        }

        public void setValidFrom(String validFrom) {
            this.validFrom = validFrom;
        }

        public String getValidTo() {
            return validTo;
        }

        public void setValidTo(String validTo) {
            this.validTo = validTo;
        }

        public String getDecryptUntil() {
            return decryptUntil;
        }

        public void setDecryptUntil(String decryptUntil) {
            this.decryptUntil = decryptUntil;
        }
    }

    public static class RevokeBusinessKeyRequest {
        private String keyId;
        private String kmsKeyRef;
        private String reason;
        private String idempotencyKey;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getKmsKeyRef() {
            return kmsKeyRef;
        }

        public void setKmsKeyRef(String kmsKeyRef) {
            this.kmsKeyRef = kmsKeyRef;
        }

        public String getReason() {
            return reason;
        }

        public void setReason(String reason) {
            this.reason = reason;
        }

        public String getIdempotencyKey() {
            return idempotencyKey;
        }

        public void setIdempotencyKey(String idempotencyKey) {
            this.idempotencyKey = idempotencyKey;
        }
    }

    public static class RevokeBusinessKeyResponse {
        private String keyId;
        private String state;
        private String changedAt;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getChangedAt() {
            return changedAt;
        }

        public void setChangedAt(String changedAt) {
            this.changedAt = changedAt;
        }
    }
}
