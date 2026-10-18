package net.hwyz.iov.cloud.framework.security.crypto.client;

import feign.FeignException;
import feign.Request;
import feign.Response;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyNotFoundException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyStateNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * FeignKmsClient 业务密钥 Provider 契约与异常分类测试（FW-SEC-DSN-CR-011 §6/§10）。
 * <p>
 * 覆盖：固定路径与 HTTP Method、统一错误体解析、结构化 NOT_FOUND 与非契约 404 区分、
 * 409/410/401/403/429/5xx/超时/outcome unknown、capability/reconcile。
 */
class FeignKmsClientBusinessKeyTest {

    private CryptoProperties properties;
    private KmsFeignClient kmsFeignClient;
    private CryptoMetrics cryptoMetrics;
    private FeignKmsClient kmsClient;

    @BeforeEach
    void setUp() {
        properties = new CryptoProperties();
        kmsFeignClient = mock(KmsFeignClient.class);
        cryptoMetrics = mock(CryptoMetrics.class);
        kmsClient = new FeignKmsClient(properties, kmsFeignClient, cryptoMetrics);
    }

    // ==================== 固定路径与 HTTP Method 契约 ====================

    @Test
    void feignContract_freezesFixedPathsAndMethods() throws Exception {
        assertMapping("createBusinessKey", "POST", "/v1/business-key/keys");
        assertMapping("wrapBusinessKey", "POST", "/v1/business-key/keys/{keyId}/wrap");
        assertMapping("getBusinessKeyMetadata", "GET", "/v1/business-key/keys/{keyId}");
        assertMapping("revokeBusinessKey", "POST", "/v1/business-key/keys/{keyId}/revoke");
        assertMapping("getBusinessKeyOperation", "GET", "/v1/business-key/operations/{operationId}");
        assertMapping("getBusinessKeyCapabilities", "GET", "/v1/business-key/capabilities");
    }

    private void assertMapping(String methodName, String http, String path) throws Exception {
        Method method = Arrays.stream(KmsFeignClient.class.getMethods())
                .filter(m -> m.getName().equals(methodName))
                .findFirst().orElseThrow();
        if ("POST".equals(http)) {
            PostMapping mapping = method.getAnnotation(PostMapping.class);
            assertNotNull(mapping, methodName + " must be POST");
            assertArrayEquals(new String[]{path}, mapping.value(), methodName);
        } else {
            GetMapping mapping = method.getAnnotation(GetMapping.class);
            assertNotNull(mapping, methodName + " must be GET");
            assertArrayEquals(new String[]{path}, mapping.value(), methodName);
        }
    }

    // ==================== create ====================

    @Test
    void createDataKey_success_mapsMaterialAndRequestFields() {
        FeignKmsClient.CreateBusinessKeyResponse response = new FeignKmsClient.CreateBusinessKeyResponse();
        response.setKeyId("k-1");
        response.setKmsKeyRef("openbao-business-key://business-key/keys/k-1");
        response.setKmsKeyVersion(3);
        response.setProvider("openbao-business-key");
        response.setAlgorithm("AES_256");
        response.setKeySpec("256");
        response.setValidFrom("2026-10-01T00:00:00Z");
        when(kmsFeignClient.createBusinessKey(any())).thenReturn(response);

        KmsKeyMaterial material = kmsClient.createDataKey(new KmsCreateKeyCommand(
                "V2C_COMM_ROOT", "op-1", "idem-1", "AES_256", "256", null, null, "audit-digest"));

        assertNotNull(material);
        assertEquals("k-1", material.keyId());
        assertEquals(3, material.kmsKeyVersion());
        verify(kmsFeignClient).createBusinessKey(argThat(r ->
                "op-1".equals(r.getOperationId())
                        && "idem-1".equals(r.getIdempotencyKey())
                        && "AES_256".equals(r.getAlgorithm())
                        && "audit-digest".equals(r.getAuditContextDigest())));
        verify(cryptoMetrics).recordBusinessKeyProviderIdempotency("accepted");
    }

    @Test
    void createDataKey_http404_unsupportedPath_mapsDependencyUnavailable() {
        when(kmsFeignClient.createBusinessKey(any()))
                .thenThrow(feignException(404, "{\"errors\":[\"unsupported path\"]}"));

        CryptoDependencyUnavailableException ex = assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.createDataKey(command()));
        assertNotNull(ex.getMessage());
    }

    @Test
    void createDataKey_http404_structuredNotFound_stillDependencyUnavailable() {
        // create/capability 路径上的 404 一律不可归为业务密钥不存在
        when(kmsFeignClient.createBusinessKey(any()))
                .thenThrow(feignException(404, "{\"code\":\"BUSINESS_KEY_NOT_FOUND\"}"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.createDataKey(command()));
    }

    @Test
    void createDataKey_http409_idempotencyConflict() {
        when(kmsFeignClient.createBusinessKey(any()))
                .thenThrow(feignException(409, "{\"code\":\"IDEMPOTENCY_CONFLICT\"}"));

        assertThrows(BusinessKeyIdempotencyConflictException.class,
                () -> kmsClient.createDataKey(command()));
        verify(cryptoMetrics).recordBusinessKeyProviderIdempotency("conflict");
    }

    @Test
    void createDataKey_http500_outcomeUnknownCarriesOperationId() {
        when(kmsFeignClient.createBusinessKey(any()))
                .thenThrow(feignException(500, "{\"code\":\"PROVIDER_ERROR\"}"));

        CryptoOperationOutcomeUnknownException ex = assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> kmsClient.createDataKey(command()));
        assertEquals("op-1", ex.getOperationId());
        verify(cryptoMetrics).recordBusinessKeyProviderOutcomeUnknown();
    }

    @Test
    void createDataKey_timeout_outcomeUnknown() {
        when(kmsFeignClient.createBusinessKey(any()))
                .thenThrow(new RuntimeException(new java.net.SocketTimeoutException("read timed out")));

        assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> kmsClient.createDataKey(command()));
    }

    @Test
    void createDataKey_connectRefused_dependencyUnavailable() {
        when(kmsFeignClient.createBusinessKey(any()))
                .thenThrow(new RuntimeException(new java.net.ConnectException("connection refused")));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.createDataKey(command()));
    }

    // ==================== getKeyMetadata ====================

    @Test
    void getKeyMetadata_http404_structuredNotFound_andCapabilityReady_mapsNotFound() {
        givenCapabilityReady();
        when(kmsFeignClient.getBusinessKeyMetadata(anyString()))
                .thenThrow(feignException(404, "{\"code\":\"BUSINESS_KEY_NOT_FOUND\"}"));

        assertThrows(BusinessKeyNotFoundException.class,
                () -> kmsClient.getKeyMetadata(new KmsKeyReference("k-1", "bk/k-1")));
    }

    @Test
    void getKeyMetadata_http404_structuredNotFound_butCapabilityNotReady_mapsDependencyUnavailable() {
        when(kmsFeignClient.getBusinessKeyMetadata(anyString()))
                .thenThrow(feignException(404, "{\"code\":\"BUSINESS_KEY_NOT_FOUND\"}"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.getKeyMetadata(new KmsKeyReference("k-1", "bk/k-1")));
    }

    @Test
    void getKeyMetadata_http404_nonContractHtml_mapsDependencyUnavailable() {
        givenCapabilityReady();
        when(kmsFeignClient.getBusinessKeyMetadata(anyString()))
                .thenThrow(feignException(404, "<html><body>404 Not Found</body></html>"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.getKeyMetadata(new KmsKeyReference("k-1", "bk/k-1")));
    }

    @Test
    void getKeyMetadata_http500_readOnly_mapsDependencyUnavailable() {
        when(kmsFeignClient.getBusinessKeyMetadata(anyString()))
                .thenThrow(feignException(503, "{\"code\":\"NOT_READY\"}"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.getKeyMetadata(new KmsKeyReference("k-1", "bk/k-1")));
    }

    @Test
    void getKeyMetadata_success_mapsState() {
        FeignKmsClient.BusinessKeyMetadataResponse response = new FeignKmsClient.BusinessKeyMetadataResponse();
        response.setKeyId("k-1");
        response.setKmsKeyRef("bk/k-1");
        response.setKmsKeyVersion(3);
        response.setState("DEPRECATED");
        response.setDecryptUntil("2026-12-31T00:00:00Z");
        when(kmsFeignClient.getBusinessKeyMetadata("k-1")).thenReturn(response);

        KmsKeyMetadata meta = kmsClient.getKeyMetadata(new KmsKeyReference("k-1", "bk/k-1"));

        assertNotNull(meta);
        assertEquals(CryptoKeyState.DEPRECATED, meta.state());
        assertEquals(Instant.parse("2026-12-31T00:00:00Z"), meta.decryptUntil());
    }

    // ==================== wrap / revoke ====================

    @Test
    void wrapKey_success_mapsWrappedAndRecipient() {
        FeignKmsClient.WrapBusinessKeyResponse response = new FeignKmsClient.WrapBusinessKeyResponse();
        response.setWrapped(new byte[]{9, 8, 7});
        response.setKeyId("k-1");
        response.setKmsKeyVersion(3);
        response.setWrappingAlgorithm("RSA-OAEP-256");
        when(kmsFeignClient.wrapBusinessKey(eq("k-1"), any())).thenReturn(response);

        KmsWrappedKey wrapped = kmsClient.wrapKey(new KmsKeyReference("k-1", "bk/k-1"),
                KmsRecipient.deviceCertificate("cert-001", new byte[]{1}, "fp", new byte[]{2}, null),
                "op-w", "idem-w");

        assertNotNull(wrapped);
        assertArrayEquals(new byte[]{9, 8, 7}, wrapped.wrapped());
        assertEquals("RSA-OAEP-256", wrapped.algorithm());
        verify(kmsFeignClient).wrapBusinessKey(eq("k-1"), argThat(r ->
                "op-w".equals(r.getOperationId()) && "idem-w".equals(r.getIdempotencyKey())
                        && "DEVICE_CERT_PUBLIC_KEY".equals(r.getMode())
                        && "cert-001".equals(r.getRecipient().getCertSerial())
                        && "fp".equals(r.getRecipient().getCertificateSha256())));
    }

    @Test
    void wrapKey_http410_revoked_mapsStateNotAllowed() {
        when(kmsFeignClient.wrapBusinessKey(anyString(), any()))
                .thenThrow(feignException(410, "{\"code\":\"BUSINESS_KEY_REVOKED\"}"));

        assertThrows(BusinessKeyStateNotAllowedException.class,
                () -> kmsClient.wrapKey(new KmsKeyReference("k-1", "bk/k-1"),
                        KmsRecipient.deviceCertificate("cert-001"), "op-w", "idem-w"));
    }

    @Test
    void wrapKey_http403_mapsDependencyUnavailableWithoutRetryWidening() {
        when(kmsFeignClient.wrapBusinessKey(anyString(), any()))
                .thenThrow(feignException(403, "{\"code\":\"FORBIDDEN\"}"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.wrapKey(new KmsKeyReference("k-1", "bk/k-1"),
                        KmsRecipient.deviceCertificate("cert-001"), "op-w", "idem-w"));
    }

    @Test
    void wrapKey_http429_mapsDependencyUnavailable() {
        when(kmsFeignClient.wrapBusinessKey(anyString(), any()))
                .thenThrow(feignException(429, "{\"code\":\"RATE_LIMITED\"}"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.wrapKey(new KmsKeyReference("k-1", "bk/k-1"),
                        KmsRecipient.deviceCertificate("cert-001"), "op-w", "idem-w"));
    }

    @Test
    void wrapKey_http422_unsupportedAlgorithm_mapsDependencyUnavailable() {
        when(kmsFeignClient.wrapBusinessKey(anyString(), any()))
                .thenThrow(feignException(422, "{\"code\":\"UNSUPPORTED_ALGORITHM\"}"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.wrapKey(new KmsKeyReference("k-1", "bk/k-1"),
                        KmsRecipient.deviceCertificate("cert-001"), "op-w", "idem-w"));
    }

    @Test
    void revokeKey_success_mapsResult() {
        FeignKmsClient.RevokeBusinessKeyResponse response = new FeignKmsClient.RevokeBusinessKeyResponse();
        response.setKeyId("k-1");
        response.setState("REVOKED");
        response.setChangedAt("2026-10-08T00:00:00Z");
        when(kmsFeignClient.revokeBusinessKey(eq("k-1"), any())).thenReturn(response);

        KmsRevocationResult result = kmsClient.revokeKey(
                new KmsKeyReference("k-1", "bk/k-1"), "ROTATION", "idem-r", "op-r");

        assertNotNull(result);
        assertEquals(CryptoKeyState.REVOKED, result.state());
        verify(kmsFeignClient).revokeBusinessKey(eq("k-1"), argThat(r ->
                "idem-r".equals(r.getIdempotencyKey()) && "ROTATION".equals(r.getReasonCode())
                        && "op-r".equals(r.getOperationId())));
    }

    @Test
    void revokeKey_http503_outcomeUnknown() {
        when(kmsFeignClient.revokeBusinessKey(anyString(), any()))
                .thenThrow(feignException(503, "{\"code\":\"PROVIDER_ERROR\"}"));

        CryptoOperationOutcomeUnknownException ex = assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> kmsClient.revokeKey(new KmsKeyReference("k-1", "bk/k-1"), "REVOKE", "idem-r", "op-r"));
        assertEquals("op-r", ex.getOperationId());
    }

    // ==================== reconcile / capabilities ====================

    @Test
    void getOperation_mapsStateAndResultRef() {
        FeignKmsClient.OperationResponse response = new FeignKmsClient.OperationResponse();
        response.setOperationId("op-1");
        response.setState("SUCCEEDED");
        response.setResultRef("k-1");
        when(kmsFeignClient.getBusinessKeyOperation("op-1")).thenReturn(response);

        KmsOperationResult result = kmsClient.getOperation("op-1");

        assertEquals(KmsOperationState.SUCCEEDED, result.state());
        assertTrue(result.succeeded());
        assertEquals("k-1", result.resultRef());
    }

    @Test
    void getOperation_unknownState_mapsUnknown() {
        FeignKmsClient.OperationResponse response = new FeignKmsClient.OperationResponse();
        response.setState("SOMETHING_ELSE");
        when(kmsFeignClient.getBusinessKeyOperation("op-1")).thenReturn(response);

        assertEquals(KmsOperationState.UNKNOWN, kmsClient.getOperation("op-1").state());
    }

    @Test
    void getCapabilities_mapsAndMarksReady() {
        when(kmsFeignClient.getBusinessKeyCapabilities()).thenReturn(capabilitiesResponse());

        KmsProviderCapabilities capabilities = kmsClient.getCapabilities();

        assertTrue(capabilities.isReady());
        assertTrue(capabilities.supportsWrapMode("DEVICE_CERT_PUBLIC_KEY"));
        assertEquals("openbao-business-key", capabilities.provider());
        verify(cryptoMetrics).recordBusinessKeyProviderRequest("capabilities", "success");
    }

    @Test
    void getCapabilities_mapsDerivedEnvelopeAndResultStore() {
        FeignKmsClient.CapabilitiesResponse response = capabilitiesResponse();
        response.setAlgorithms(List.of("ECDH_P256", "HKDF_SHA256", "AES_256_GCM"));
        response.setDerivedEnvelopeVersions(List.of("v1"));
        response.setResultStoreReady(true);
        when(kmsFeignClient.getBusinessKeyCapabilities()).thenReturn(response);

        KmsProviderCapabilities capabilities = kmsClient.getCapabilities();

        assertTrue(capabilities.supportsDerivedEnvelope("v1"));
        assertTrue(capabilities.supportsAlgorithm("ECDH_P256"));
        assertTrue(capabilities.supportsAlgorithm("HKDF_SHA256"));
        assertTrue(capabilities.supportsAlgorithm("AES_256_GCM"));
        assertTrue(capabilities.resultStoreReady());
    }

    @Test
    void getCapabilities_resultStoreFalse_mappedAsNotReady() {
        FeignKmsClient.CapabilitiesResponse response = capabilitiesResponse();
        response.setDerivedEnvelopeVersions(List.of("v1"));
        response.setResultStoreReady(false);
        when(kmsFeignClient.getBusinessKeyCapabilities()).thenReturn(response);

        assertFalse(kmsClient.getCapabilities().resultStoreReady());
    }

    @Test
    void getCapabilities_failure_marksDown() {
        when(kmsFeignClient.getBusinessKeyCapabilities())
                .thenThrow(feignException(404, "{\"errors\":[\"unsupported path\"]}"));

        assertThrows(CryptoDependencyUnavailableException.class, () -> kmsClient.getCapabilities());
    }

    // ==================== helpers ====================

    private void givenCapabilityReady() {
        when(kmsFeignClient.getBusinessKeyCapabilities()).thenReturn(capabilitiesResponse());
        kmsClient.getCapabilities();
    }

    private FeignKmsClient.CapabilitiesResponse capabilitiesResponse() {
        FeignKmsClient.CapabilitiesResponse response = new FeignKmsClient.CapabilitiesResponse();
        response.setProvider("openbao-business-key");
        response.setApiVersion("v1");
        response.setMount("business-key");
        response.setStorageReady(true);
        response.setMountReady(true);
        response.setAlgorithms(List.of("AES_256"));
        response.setWrapModes(List.of("DEVICE_CERT_PUBLIC_KEY", "RUNTIME", "DEVICE_ROOT_KEK"));
        return response;
    }

    private KmsCreateKeyCommand command() {
        return new KmsCreateKeyCommand("V2C_COMM_ROOT", "op-1", "idem-1",
                "AES_256", "256", null, null, "audit-digest");
    }

    private FeignException feignException(int status, String body) {
        Request request = Request.create(Request.HttpMethod.POST,
                "http://kms/v1/business-key/keys", Collections.emptyMap(),
                new byte[0], StandardCharsets.UTF_8);
        Response response = Response.builder()
                .status(status)
                .reason("reason")
                .request(request)
                .body(body != null ? body.getBytes(StandardCharsets.UTF_8) : new byte[0])
                .build();
        return FeignException.errorStatus("POST /v1/business-key/keys", response);
    }
}
