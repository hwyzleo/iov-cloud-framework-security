package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyNotFoundException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyStateNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KdfParams;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Feign KMS客户端实现（FW-SEC-DSN-CR-011 冻结 wire contract）。
 * <p>
 * 运行期业务密钥材料改走独立 OpenBao business-key Provider 契约（{@code /v1/business-key/...}）；
 * 标准 Transit 只保留通用原语职责，禁止再调用虚构的 {@code /v1/transit/business-key/*}。
 */
public class FeignKmsClient implements KmsClient {

    private static final Pattern ERROR_CODE = Pattern.compile("\"code\"\\s*:\\s*\"([^\"]+)\"");

    private final CryptoProperties properties;
    private final KmsFeignClient kmsFeignClient;
    private final CryptoMetrics cryptoMetrics;

    /**
     * 最近一次探测的 Provider 能力状态；未探测/探测失败视为 DOWN（fail-closed）。
     */
    private volatile boolean capabilityReady = false;

    public FeignKmsClient(CryptoProperties properties, KmsFeignClient kmsFeignClient) {
        this(properties, kmsFeignClient, null);
    }

    public FeignKmsClient(CryptoProperties properties, KmsFeignClient kmsFeignClient,
                          CryptoMetrics cryptoMetrics) {
        this.properties = properties;
        this.kmsFeignClient = kmsFeignClient;
        this.cryptoMetrics = cryptoMetrics;
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

    // ==================== 业务密钥材料 Provider（FW-SEC-DSN-CR-011 §6） ====================

    @Override
    public KmsKeyMaterial createDataKey(KmsCreateKeyCommand command) {
        long start = System.currentTimeMillis();
        try {
            CreateBusinessKeyRequest request = new CreateBusinessKeyRequest();
            request.setOperationId(command.operationId());
            request.setIdempotencyKey(command.idempotencyKey());
            request.setAlgorithm(command.algorithm());
            request.setKeySpec(command.keySpec());
            request.setValidFrom(toIso(command.validFrom()));
            request.setValidTo(toIso(command.validTo()));
            request.setAuditContextDigest(command.auditContextDigest());
            CreateBusinessKeyResponse response = kmsFeignClient.createBusinessKey(request);
            recordSuccess("create", start);
            if (cryptoMetrics != null) {
                cryptoMetrics.recordBusinessKeyProviderIdempotency("accepted");
            }
            return mapKeyMaterial(response);
        } catch (CryptoException e) {
            recordFailure("create", start, e);
            throw e;
        } catch (Exception e) {
            recordFailure("create", start, e);
            // create 路径上的 404 只能表示路由/Provider 异常，绝不可归为业务密钥不存在
            throw classify(e, "create business key", false, true, command.operationId());
        }
    }

    @Override
    public KmsWrappedKey wrapKey(KmsKeyReference keyRef, KmsRecipient recipient,
                                 String operationId, String idempotencyKey) {
        long start = System.currentTimeMillis();
        try {
            WrapBusinessKeyRequest request = new WrapBusinessKeyRequest();
            request.setOperationId(operationId);
            request.setIdempotencyKey(idempotencyKey);
            request.setMode(recipient.mode() != null ? recipient.mode().name() : null);
            request.setRecipient(toRecipient(recipient));
            WrapBusinessKeyResponse response = kmsFeignClient.wrapBusinessKey(keyRef.keyId(), request);
            recordSuccess("wrap", start);
            if (cryptoMetrics != null) {
                cryptoMetrics.recordBusinessKeyProviderIdempotency("accepted");
            }
            return mapWrappedKey(response);
        } catch (CryptoException e) {
            recordFailure("wrap", start, e);
            throw e;
        } catch (Exception e) {
            recordFailure("wrap", start, e);
            throw classify(e, "wrap business key", true, true, operationId);
        }
    }

    @Override
    public KmsKeyMetadata getKeyMetadata(KmsKeyReference keyRef) {
        long start = System.currentTimeMillis();
        try {
            BusinessKeyMetadataResponse response = kmsFeignClient.getBusinessKeyMetadata(keyRef.keyId());
            recordSuccess("metadata", start);
            return mapKeyMetadata(response);
        } catch (CryptoException e) {
            recordFailure("metadata", start, e);
            throw e;
        } catch (Exception e) {
            recordFailure("metadata", start, e);
            throw classify(e, "get business key metadata", true, false, null);
        }
    }

    @Override
    public KmsRevocationResult revokeKey(KmsKeyReference keyRef, String reason, String idempotencyKey,
                                         String operationId) {
        long start = System.currentTimeMillis();
        try {
            RevokeBusinessKeyRequest request = new RevokeBusinessKeyRequest();
            request.setOperationId(operationId);
            request.setIdempotencyKey(idempotencyKey);
            request.setReasonCode(reason);
            RevokeBusinessKeyResponse response = kmsFeignClient.revokeBusinessKey(keyRef.keyId(), request);
            recordSuccess("revoke", start);
            if (cryptoMetrics != null) {
                cryptoMetrics.recordBusinessKeyProviderIdempotency("accepted");
            }
            return new KmsRevocationResult(
                    response.getKeyId(),
                    parseState(response.getState()),
                    response.getChangedAt() != null ? Instant.parse(response.getChangedAt()) : null);
        } catch (CryptoException e) {
            recordFailure("revoke", start, e);
            throw e;
        } catch (Exception e) {
            recordFailure("revoke", start, e);
            throw classify(e, "revoke business key", true, true, operationId);
        }
    }

    @Override
    public KmsOperationResult getOperation(String operationId) {
        long start = System.currentTimeMillis();
        try {
            OperationResponse response = kmsFeignClient.getBusinessKeyOperation(operationId);
            recordSuccess("reconcile", start);
            return new KmsOperationResult(
                    response.getOperationId() != null ? response.getOperationId() : operationId,
                    parseOperationState(response.getState()),
                    response.getResultRef(),
                    response.getMessage());
        } catch (CryptoException e) {
            recordFailure("reconcile", start, e);
            throw e;
        } catch (Exception e) {
            recordFailure("reconcile", start, e);
            throw classify(e, "reconcile business key operation", true, false, operationId);
        }
    }

    @Override
    public KmsProviderCapabilities getCapabilities() {
        long start = System.currentTimeMillis();
        try {
            CapabilitiesResponse response = kmsFeignClient.getBusinessKeyCapabilities();
            KmsProviderCapabilities capabilities = mapCapabilities(response);
            this.capabilityReady = capabilities.isReady();
            recordSuccess("capabilities", start);
            return capabilities;
        } catch (Exception e) {
            this.capabilityReady = false;
            recordFailure("capabilities", start, e);
            throw classify(e, "get business key capabilities", false, false, null);
        }
    }

    // ==================== 异常分类（FW-SEC-DSN-CR-011 §6.6） ====================

    /**
     * 业务密钥 Provider 失败分类矩阵（FW-SEC-DSN-CR-011 §6.6）。
     *
     * @param allowStructuredNotFound 是否允许把结构化 BUSINESS_KEY_NOT_FOUND 映射为 NotFound
     *                                （create/capabilities 恒为 false）
     * @param writeOperation          是否写操作（已发送后 5xx/超时转 outcome unknown）
     * @param operationId             写操作 operationId（用于对账提示）
     */
    private CryptoException classify(Exception e, String op, boolean allowStructuredNotFound,
                                     boolean writeOperation, String operationId) {
        // 连接建立前失败：可证明请求体未发送，可按预算重试
        if (findCause(e, ConnectException.class) != null || findCause(e, UnknownHostException.class) != null) {
            return new CryptoDependencyUnavailableException(
                    op + " unavailable (request not sent)", e);
        }
        // 请求可能已发送：结果未知
        if (findCause(e, SocketTimeoutException.class) != null) {
            return outcomeUnknown(op, operationId, "timeout", e);
        }

        feign.FeignException fe = findCause(e, feign.FeignException.class);
        if (fe != null) {
            int status = fe.status();
            KmsErrorCode code = extractErrorCode(fe);
            switch (status) {
                case 404:
                    if (allowStructuredNotFound && capabilityReady && code == KmsErrorCode.BUSINESS_KEY_NOT_FOUND) {
                        return new BusinessKeyNotFoundException(op + " not found (http 404)", e);
                    }
                    return new CryptoDependencyUnavailableException(
                            op + " provider route/mount unavailable (http 404, code=" + code + ")", e);
                case 409:
                    if (cryptoMetrics != null) {
                        cryptoMetrics.recordBusinessKeyProviderIdempotency("conflict");
                    }
                    return new BusinessKeyIdempotencyConflictException(
                            op + " idempotency conflict (http 409)", e);
                case 410:
                    return new BusinessKeyStateNotAllowedException(
                            op + " key revoked/expired (http 410, code=" + code + ")", e);
                case 400:
                case 422:
                    return new CryptoDependencyUnavailableException(
                            op + " invalid/unsupported request (http " + status + ", code=" + code + ")", e);
                case 401:
                case 403:
                    return new CryptoDependencyUnavailableException(
                            op + " authentication/authorization failed (http " + status + ", code=" + code + ")", e);
                case 429:
                    return new CryptoDependencyUnavailableException(
                            op + " rate limited (http 429, code=" + code + ")", e);
                default:
                    if (status < 0 || status >= 500) {
                        return writeOperation
                                ? outcomeUnknown(op, operationId, "http " + status, e)
                                : new CryptoDependencyUnavailableException(
                                        op + " provider not ready (http " + status + ", code=" + code + ")", e);
                    }
                    return new CryptoDependencyUnavailableException(
                            op + " failed (http " + status + ", code=" + code + ")", e);
            }
        }

        if (findCause(e, feign.RetryableException.class) != null) {
            return outcomeUnknown(op, operationId, "retryable", e);
        }
        return new CryptoDependencyUnavailableException(op + " failed", e);
    }

    private CryptoOperationOutcomeUnknownException outcomeUnknown(String op, String operationId,
                                                                  String detail, Throwable cause) {
        if (cryptoMetrics != null) {
            cryptoMetrics.recordBusinessKeyProviderOutcomeUnknown();
        }
        String message = op + " outcome unknown (" + detail + ")"
                + (operationId != null ? "; reconcile with original operationId=" + operationId : "");
        return new CryptoOperationOutcomeUnknownException(message, cause, operationId);
    }

    /**
     * 解析统一错误体 {@code {"code": "...", ...}}；非契约错误体/HTML/OpenBao 原生 errors 体一律 UNKNOWN。
     */
    private KmsErrorCode extractErrorCode(feign.FeignException fe) {
        try {
            String body = fe.contentUTF8();
            if (body == null || body.isBlank()) {
                return KmsErrorCode.UNKNOWN;
            }
            String trimmed = body.trim();
            if (trimmed.startsWith("<")) {
                return KmsErrorCode.UNKNOWN;
            }
            Matcher matcher = ERROR_CODE.matcher(body);
            if (matcher.find()) {
                return KmsErrorCode.fromWire(matcher.group(1));
            }
            return KmsErrorCode.UNKNOWN;
        } catch (Exception ignore) {
            return KmsErrorCode.UNKNOWN;
        }
    }

    private static <T extends Throwable> T findCause(Throwable t, Class<T> type) {
        Throwable current = t;
        int depth = 0;
        while (current != null && depth < 8) {
            if (type.isInstance(current)) {
                return type.cast(current);
            }
            current = current.getCause();
            depth++;
        }
        return null;
    }

    private void recordSuccess(String operation, long start) {
        if (cryptoMetrics != null) {
            cryptoMetrics.recordBusinessKeyProviderRequest(operation, "success");
            cryptoMetrics.recordBusinessKeyProviderLatency(operation, System.currentTimeMillis() - start);
        }
    }

    private void recordFailure(String operation, long start, Throwable error) {
        if (cryptoMetrics != null) {
            String result = error instanceof CryptoOperationOutcomeUnknownException
                    ? "outcome-unknown" : "error";
            cryptoMetrics.recordBusinessKeyProviderRequest(operation, result);
            cryptoMetrics.recordBusinessKeyProviderLatency(operation, System.currentTimeMillis() - start);
        }
    }

    private static String toIso(Instant instant) {
        return instant != null ? instant.toString() : null;
    }

    private WrapRecipient toRecipient(KmsRecipient recipient) {
        WrapRecipient wire = new WrapRecipient();
        wire.setCertSerial(recipient.certSerial());
        wire.setCertificateDer(recipient.certificateDer());
        wire.setCertificateSha256(recipient.certificateSha256Fingerprint());
        wire.setSpki(recipient.spki());
        wire.setAllowedAlgorithms(recipient.allowedAlgorithms());
        wire.setAudience(recipient.audience());
        wire.setRuntimeKeyRef(recipient.runtimeKeyRef());
        wire.setWrappingKeyRef(recipient.wrappingKeyRef());
        return wire;
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
        String algorithm = response.getWrappingAlgorithm() != null
                ? response.getWrappingAlgorithm() : response.getAlgorithm();
        return new KmsWrappedKey(
                response.getWrapped(),
                response.getKeyId(),
                response.getKmsKeyVersion(),
                algorithm,
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

    private KmsProviderCapabilities mapCapabilities(CapabilitiesResponse response) {
        boolean storageReady = Boolean.TRUE.equals(response.getStorageReady());
        boolean mountReady = Boolean.TRUE.equals(response.getMountReady());
        boolean ready = Boolean.TRUE.equals(response.getReady()) || (storageReady && mountReady);
        return new KmsProviderCapabilities(
                response.getProvider(),
                response.getApiVersion(),
                response.getMount(),
                ready,
                storageReady,
                mountReady,
                toSet(response.getAlgorithms()),
                toSet(response.getWrapModes()));
    }

    private static java.util.Set<String> toSet(List<String> values) {
        if (values == null) {
            return java.util.Set.of();
        }
        return new java.util.TreeSet<>(values);
    }

    private KmsOperationState parseOperationState(String state) {
        if (state == null) {
            return KmsOperationState.UNKNOWN;
        }
        try {
            return KmsOperationState.valueOf(state.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return KmsOperationState.UNKNOWN;
        }
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

    // ==================== 通用 Transit DTO ====================

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

    // ==================== 业务密钥材料 Provider DTO（FW-SEC-DSN-CR-011 §6） ====================

    public static class CreateBusinessKeyRequest {
        private String operationId;
        private String idempotencyKey;
        private String algorithm;
        private String keySpec;
        private String validFrom;
        private String validTo;
        private String auditContextDigest;

        public String getOperationId() {
            return operationId;
        }

        public void setOperationId(String operationId) {
            this.operationId = operationId;
        }

        public String getIdempotencyKey() {
            return idempotencyKey;
        }

        public void setIdempotencyKey(String idempotencyKey) {
            this.idempotencyKey = idempotencyKey;
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

        public String getAuditContextDigest() {
            return auditContextDigest;
        }

        public void setAuditContextDigest(String auditContextDigest) {
            this.auditContextDigest = auditContextDigest;
        }
    }

    public static class CreateBusinessKeyResponse {
        private String keyId;
        private String kmsKeyRef;
        private Integer kmsKeyVersion;
        private String provider;
        private String algorithm;
        private String keySpec;
        private String state;
        private String validFrom;
        private String validTo;
        private String operationId;

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

        public String getOperationId() {
            return operationId;
        }

        public void setOperationId(String operationId) {
            this.operationId = operationId;
        }
    }

    public static class WrapBusinessKeyRequest {
        private String operationId;
        private String idempotencyKey;
        private String mode;
        private WrapRecipient recipient;

        public String getOperationId() {
            return operationId;
        }

        public void setOperationId(String operationId) {
            this.operationId = operationId;
        }

        public String getIdempotencyKey() {
            return idempotencyKey;
        }

        public void setIdempotencyKey(String idempotencyKey) {
            this.idempotencyKey = idempotencyKey;
        }

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }

        public WrapRecipient getRecipient() {
            return recipient;
        }

        public void setRecipient(WrapRecipient recipient) {
            this.recipient = recipient;
        }
    }

    public static class WrapRecipient {
        private String certSerial;
        private byte[] certificateDer;
        private String certificateSha256;
        private byte[] spki;
        private List<String> allowedAlgorithms;
        private String audience;
        private String runtimeKeyRef;
        private String wrappingKeyRef;

        public String getCertSerial() {
            return certSerial;
        }

        public void setCertSerial(String certSerial) {
            this.certSerial = certSerial;
        }

        public byte[] getCertificateDer() {
            return certificateDer;
        }

        public void setCertificateDer(byte[] certificateDer) {
            this.certificateDer = certificateDer;
        }

        public String getCertificateSha256() {
            return certificateSha256;
        }

        public void setCertificateSha256(String certificateSha256) {
            this.certificateSha256 = certificateSha256;
        }

        public byte[] getSpki() {
            return spki;
        }

        public void setSpki(byte[] spki) {
            this.spki = spki;
        }

        public List<String> getAllowedAlgorithms() {
            return allowedAlgorithms;
        }

        public void setAllowedAlgorithms(List<String> allowedAlgorithms) {
            this.allowedAlgorithms = allowedAlgorithms;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getRuntimeKeyRef() {
            return runtimeKeyRef;
        }

        public void setRuntimeKeyRef(String runtimeKeyRef) {
            this.runtimeKeyRef = runtimeKeyRef;
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
        private String wrappingAlgorithm;
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

        public String getWrappingAlgorithm() {
            return wrappingAlgorithm;
        }

        public void setWrappingAlgorithm(String wrappingAlgorithm) {
            this.wrappingAlgorithm = wrappingAlgorithm;
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
        private String createdAt;
        private String revokedAt;
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

        public String getCreatedAt() {
            return createdAt;
        }

        public void setCreatedAt(String createdAt) {
            this.createdAt = createdAt;
        }

        public String getRevokedAt() {
            return revokedAt;
        }

        public void setRevokedAt(String revokedAt) {
            this.revokedAt = revokedAt;
        }

        public String getDecryptUntil() {
            return decryptUntil;
        }

        public void setDecryptUntil(String decryptUntil) {
            this.decryptUntil = decryptUntil;
        }
    }

    public static class RevokeBusinessKeyRequest {
        private String operationId;
        private String idempotencyKey;
        private String reasonCode;

        public String getOperationId() {
            return operationId;
        }

        public void setOperationId(String operationId) {
            this.operationId = operationId;
        }

        public String getIdempotencyKey() {
            return idempotencyKey;
        }

        public void setIdempotencyKey(String idempotencyKey) {
            this.idempotencyKey = idempotencyKey;
        }

        public String getReasonCode() {
            return reasonCode;
        }

        public void setReasonCode(String reasonCode) {
            this.reasonCode = reasonCode;
        }
    }

    public static class RevokeBusinessKeyResponse {
        private String keyId;
        private String state;
        private String changedAt;
        private String operationId;

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

        public String getOperationId() {
            return operationId;
        }

        public void setOperationId(String operationId) {
            this.operationId = operationId;
        }
    }

    public static class OperationResponse {
        private String operationId;
        private String state;
        private String resultRef;
        private String message;

        public String getOperationId() {
            return operationId;
        }

        public void setOperationId(String operationId) {
            this.operationId = operationId;
        }

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getResultRef() {
            return resultRef;
        }

        public void setResultRef(String resultRef) {
            this.resultRef = resultRef;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }

    public static class CapabilitiesResponse {
        private String provider;
        private String apiVersion;
        private String mount;
        private Boolean ready;
        private Boolean storageReady;
        private Boolean mountReady;
        private List<String> algorithms;
        private List<String> wrapModes;

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getApiVersion() {
            return apiVersion;
        }

        public void setApiVersion(String apiVersion) {
            this.apiVersion = apiVersion;
        }

        public String getMount() {
            return mount;
        }

        public void setMount(String mount) {
            this.mount = mount;
        }

        public Boolean getReady() {
            return ready;
        }

        public void setReady(Boolean ready) {
            this.ready = ready;
        }

        public Boolean getStorageReady() {
            return storageReady;
        }

        public void setStorageReady(Boolean storageReady) {
            this.storageReady = storageReady;
        }

        public Boolean getMountReady() {
            return mountReady;
        }

        public void setMountReady(Boolean mountReady) {
            this.mountReady = mountReady;
        }

        public List<String> getAlgorithms() {
            return algorithms;
        }

        public void setAlgorithms(List<String> algorithms) {
            this.algorithms = algorithms;
        }

        public List<String> getWrapModes() {
            return wrapModes;
        }

        public void setWrapModes(List<String> wrapModes) {
            this.wrapModes = wrapModes;
        }
    }

    public static class ErrorResponse {
        private String code;
        private String message;
        private String operationId;
        private Boolean retryable;

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public String getOperationId() {
            return operationId;
        }

        public void setOperationId(String operationId) {
            this.operationId = operationId;
        }

        public Boolean getRetryable() {
            return retryable;
        }

        public void setRetryable(Boolean retryable) {
            this.retryable = retryable;
        }
    }
}
