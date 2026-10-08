package net.hwyz.iov.cloud.framework.security.crypto.client;

import feign.FeignException;
import feign.Request;
import feign.Response;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyNotFoundException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * FeignKmsClient 业务密钥材料方法与异常分类测试（FW-SEC-DSN-CR-009 §7/§9/§12）。
 */
class FeignKmsClientBusinessKeyTest {

    private CryptoProperties properties;
    private KmsFeignClient kmsFeignClient;
    private FeignKmsClient kmsClient;

    @BeforeEach
    void setUp() {
        properties = new CryptoProperties();
        kmsFeignClient = mock(KmsFeignClient.class);
        kmsClient = new FeignKmsClient(properties, kmsFeignClient);
    }

    // ==================== createDataKey ====================

    @Test
    void createDataKey_success_mapsMaterial() {
        FeignKmsClient.CreateBusinessKeyResponse response = new FeignKmsClient.CreateBusinessKeyResponse();
        response.setKeyId("k-1");
        response.setKmsKeyRef("bk/k-1");
        response.setKmsKeyVersion(3);
        response.setProvider("Vault-Transit");
        response.setAlgorithm("AES_256_GCM");
        response.setKeySpec("256");
        response.setValidFrom("2026-10-01T00:00:00Z");
        when(kmsFeignClient.createBusinessKey(any())).thenReturn(response);

        KmsKeyMaterial material = kmsClient.createDataKey(
                new KmsCreateKeyCommand("TBOX_DEVICE_ROOT", "AES_256_GCM", "256", "idem-1", null));

        assertNotNull(material);
        assertEquals("k-1", material.keyId());
        assertEquals(3, material.kmsKeyVersion());
        verify(kmsFeignClient).createBusinessKey(argThat(r ->
                "TBOX_DEVICE_ROOT".equals(r.getBizType()) && "idem-1".equals(r.getIdempotencyKey())));
    }

    @Test
    void createDataKey_http409_idempotencyConflict() {
        when(kmsFeignClient.createBusinessKey(any())).thenThrow(feignException(409));

        assertThrows(BusinessKeyIdempotencyConflictException.class,
                () -> kmsClient.createDataKey(new KmsCreateKeyCommand("TBOX_DEVICE_ROOT",
                        "AES_256_GCM", "256", "idem-1", null)));
    }

    @Test
    void createDataKey_http500_outcomeUnknown() {
        when(kmsFeignClient.createBusinessKey(any())).thenThrow(feignException(500));

        assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> kmsClient.createDataKey(new KmsCreateKeyCommand("TBOX_DEVICE_ROOT",
                        "AES_256_GCM", "256", "idem-1", null)));
    }

    @Test
    void createDataKey_timeout_outcomeUnknown() {
        when(kmsFeignClient.createBusinessKey(any()))
                .thenThrow(new RuntimeException(new java.net.SocketTimeoutException("read timed out")));

        assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> kmsClient.createDataKey(new KmsCreateKeyCommand("TBOX_DEVICE_ROOT",
                        "AES_256_GCM", "256", "idem-1", null)));
    }

    @Test
    void createDataKey_connectRefused_dependencyUnavailable() {
        when(kmsFeignClient.createBusinessKey(any()))
                .thenThrow(new RuntimeException(new java.net.ConnectException("connection refused")));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.createDataKey(new KmsCreateKeyCommand("TBOX_DEVICE_ROOT",
                        "AES_256_GCM", "256", "idem-1", null)));
    }

    // ==================== getKeyMetadata ====================

    @Test
    void getKeyMetadata_http404_notFound() {
        when(kmsFeignClient.getBusinessKeyMetadata(any())).thenThrow(feignException(404));

        assertThrows(BusinessKeyNotFoundException.class,
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
        when(kmsFeignClient.getBusinessKeyMetadata(any())).thenReturn(response);

        KmsKeyMetadata meta = kmsClient.getKeyMetadata(new KmsKeyReference("k-1", "bk/k-1"));

        assertNotNull(meta);
        assertEquals(CryptoKeyState.DEPRECATED, meta.state());
        assertEquals(Instant.parse("2026-12-31T00:00:00Z"), meta.decryptUntil());
    }

    // ==================== wrapKey / revokeKey ====================

    @Test
    void wrapKey_success_mapsWrapped() {
        FeignKmsClient.WrapBusinessKeyResponse response = new FeignKmsClient.WrapBusinessKeyResponse();
        response.setWrapped(new byte[]{9, 8, 7});
        response.setKeyId("k-1");
        response.setKmsKeyVersion(3);
        response.setAlgorithm("RSA-OAEP");
        when(kmsFeignClient.wrapBusinessKey(any())).thenReturn(response);

        KmsWrappedKey wrapped = kmsClient.wrapKey(new KmsKeyReference("k-1", "bk/k-1"),
                KmsRecipient.deviceCertificate("cert-001"));

        assertNotNull(wrapped);
        assertArrayEquals(new byte[]{9, 8, 7}, wrapped.wrapped());
        verify(kmsFeignClient).wrapBusinessKey(argThat(r ->
                "DEVICE_CERT_PUBLIC_KEY".equals(r.getMode()) && "cert-001".equals(r.getCertSerial())));
    }

    @Test
    void revokeKey_success_mapsResult() {
        FeignKmsClient.RevokeBusinessKeyResponse response = new FeignKmsClient.RevokeBusinessKeyResponse();
        response.setKeyId("k-1");
        response.setState("REVOKED");
        response.setChangedAt("2026-10-08T00:00:00Z");
        when(kmsFeignClient.revokeBusinessKey(any())).thenReturn(response);

        KmsRevocationResult result = kmsClient.revokeKey(
                new KmsKeyReference("k-1", "bk/k-1"), "轮换", "idem-r");

        assertNotNull(result);
        assertEquals(CryptoKeyState.REVOKED, result.state());
        verify(kmsFeignClient).revokeBusinessKey(argThat(r ->
                "idem-r".equals(r.getIdempotencyKey()) && "轮换".equals(r.getReason())));
    }

    @Test
    void revokeKey_http5xx_outcomeUnknown() {
        when(kmsFeignClient.revokeBusinessKey(any())).thenThrow(feignException(503));

        assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> kmsClient.revokeKey(new KmsKeyReference("k-1", "bk/k-1"), "吊销", "idem-r"));
    }

    private FeignException feignException(int status) {
        Request request = Request.create(Request.HttpMethod.POST,
                "http://kms/v1/transit/business-key/create", Collections.emptyMap(),
                new byte[0], StandardCharsets.UTF_8);
        Response response = Response.builder()
                .status(status)
                .reason("reason")
                .request(request)
                .body(new byte[0])
                .build();
        return FeignException.errorStatus("POST /v1/transit/business-key/create", response);
    }
}
