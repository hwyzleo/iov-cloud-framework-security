package net.hwyz.iov.cloud.framework.security.crypto.client;

import feign.FeignException;
import feign.Request;
import feign.Response;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.PostMapping;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * FeignKmsClient 根派生封装契约与异常分类测试（FW-SEC-DSN-CR-013 §7.3/§8/§10）。
 * <p>
 * 覆盖：固定路径与 HTTP Method、请求字段映射（含规范化锚原文与摘要、purpose、证书材料）、
 * 响应映射（kcv 十六进制解码）、409/422/5xx/超时/连接失败分类。
 */
class FeignKmsClientDerivedKeyTest {

    private static final String VIN = "LSVAA4187N2123456";

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

    @Test
    void feignContract_freezesDerivedKeysPath() throws Exception {
        Method method = Arrays.stream(KmsFeignClient.class.getMethods())
                .filter(m -> m.getName().equals("deriveAndWrap"))
                .findFirst().orElseThrow();
        PostMapping mapping = method.getAnnotation(PostMapping.class);
        assertNotNull(mapping, "deriveAndWrap must be POST");
        assertArrayEquals(new String[]{"/v1/business-key/derived-keys:wrap"}, mapping.value());
    }

    @Test
    void deriveAndWrap_success_mapsRequestAndResponse() {
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        FeignKmsClient.DerivedWrapResponse response = new FeignKmsClient.DerivedWrapResponse();
        response.setLogicalKeyId("logical-1");
        response.setKmsKeyRef("openbao-derived://transit/v2c-comm-root/v1/" + anchor.digest() + "/UPLINK_AEAD");
        response.setRootKeyVersion(3);
        response.setDerivationVersion("v1");
        response.setWrapped(new byte[]{9, 8, 7});
        response.setWrappingAlgorithm("RSA-OAEP-SHA256");
        response.setKcv("aabbcc");
        response.setOperationId("op-1");
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(response);

        DerivedWrappedKey result = kmsClient.deriveAndWrap(
                new KmsDerivedKeyReference("V2C_COMM_ROOT", "openbao-transit://transit/keys/v2c-comm-root"),
                new DerivationInput(anchor, KeyPurpose.UPLINK_AEAD, "v1"),
                KmsRecipient.deviceCertificate("cert-001", new byte[]{1, 2}, "fp1", new byte[]{3, 4}, null),
                new OperationContext("op-1", "idem-1"));

        assertNotNull(result);
        assertArrayEquals(new byte[]{9, 8, 7}, result.wrapped());
        assertArrayEquals(new byte[]{(byte) 0xaa, (byte) 0xbb, (byte) 0xcc}, result.kcv());
        assertEquals(3, result.rootKeyVersion());
        assertEquals("v1", result.derivationVersion());
        assertEquals("op-1", result.operationId());

        verify(kmsFeignClient).deriveAndWrap(argThat(r ->
                "V2C_COMM_ROOT".equals(r.getBizType())
                        && "v1".equals(r.getDerivationVersion())
                        && r.getAnchor() != null
                        && "VIN".equals(r.getAnchor().getType())
                        && "vin-v1".equals(r.getAnchor().getNormalizationVersion())
                        && VIN.equals(r.getAnchor().getValue())
                        && anchor.digest().equals(r.getAnchor().getDigest())
                        && "UPLINK_AEAD".equals(r.getPurpose())
                        && r.getRecipient() != null
                        && "DEVICE_CERT_PUBLIC_KEY".equals(r.getRecipient().getMode())
                        && r.getRecipient().getCertificateDer() != null
                        && "fp1".equals(r.getRecipient().getSha256Fingerprint())
                        && "op-1".equals(r.getOperationId())
                        && "idem-1".equals(r.getIdempotencyKey())));
        verify(cryptoMetrics).recordBusinessKeyProviderIdempotency("accepted");
    }

    @Test
    void deriveAndWrap_http409_idempotencyConflict() {
        when(kmsFeignClient.deriveAndWrap(any()))
                .thenThrow(feignException(409, "{\"code\":\"IDEMPOTENCY_CONFLICT\"}"));

        assertThrows(BusinessKeyIdempotencyConflictException.class, () -> kmsClient.deriveAndWrap(
                rootRef(), input(), recipient(), operation()));
        verify(cryptoMetrics).recordBusinessKeyProviderIdempotency("conflict");
    }

    @Test
    void deriveAndWrap_http422_anchorDigestMismatch_mapsDependencyUnavailable() {
        when(kmsFeignClient.deriveAndWrap(any()))
                .thenThrow(feignException(422, "{\"code\":\"ANCHOR_DIGEST_MISMATCH\"}"));

        assertThrows(CryptoDependencyUnavailableException.class, () -> kmsClient.deriveAndWrap(
                rootRef(), input(), recipient(), operation()));
    }

    @Test
    void deriveAndWrap_http500_outcomeUnknownCarriesOperationId() {
        when(kmsFeignClient.deriveAndWrap(any()))
                .thenThrow(feignException(500, "{\"code\":\"PROVIDER_ERROR\"}"));

        CryptoOperationOutcomeUnknownException ex = assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation()));
        assertEquals("op-1", ex.getOperationId());
        verify(cryptoMetrics).recordBusinessKeyProviderOutcomeUnknown();
    }

    @Test
    void deriveAndWrap_timeout_outcomeUnknown() {
        when(kmsFeignClient.deriveAndWrap(any()))
                .thenThrow(new RuntimeException(new java.net.SocketTimeoutException("read timed out")));

        assertThrows(CryptoOperationOutcomeUnknownException.class, () -> kmsClient.deriveAndWrap(
                rootRef(), input(), recipient(), operation()));
    }

    @Test
    void deriveAndWrap_connectRefused_dependencyUnavailable() {
        when(kmsFeignClient.deriveAndWrap(any()))
                .thenThrow(new RuntimeException(new java.net.ConnectException("connection refused")));

        assertThrows(CryptoDependencyUnavailableException.class, () -> kmsClient.deriveAndWrap(
                rootRef(), input(), recipient(), operation()));
    }

    @Test
    void deriveAndWrap_http404_nonContractRoute_dependencyUnavailable() {
        when(kmsFeignClient.deriveAndWrap(any()))
                .thenThrow(feignException(404, "{\"errors\":[\"unsupported path\"]}"));

        assertThrows(CryptoDependencyUnavailableException.class, () -> kmsClient.deriveAndWrap(
                rootRef(), input(), recipient(), operation()));
    }

    @Test
    void deriveAndWrap_invalidKcvHex_failsClosed() {
        FeignKmsClient.DerivedWrapResponse response = new FeignKmsClient.DerivedWrapResponse();
        response.setKcv("zz");
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(response);

        assertThrows(Exception.class, () -> kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation()));
    }

    // ==================== helpers ====================

    private KmsDerivedKeyReference rootRef() {
        return new KmsDerivedKeyReference("V2C_COMM_ROOT", "openbao-transit://transit/keys/v2c-comm-root");
    }

    private DerivationInput input() {
        return new DerivationInput(KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, "v1");
    }

    private KmsRecipient recipient() {
        return KmsRecipient.deviceCertificate("cert-001", new byte[]{1, 2}, "fp1", new byte[]{3, 4}, null);
    }

    private OperationContext operation() {
        return new OperationContext("op-1", "idem-1");
    }

    private FeignException feignException(int status, String body) {
        Request request = Request.create(Request.HttpMethod.POST,
                "http://kms/v1/business-key/derived-keys:wrap", Collections.emptyMap(),
                new byte[0], StandardCharsets.UTF_8);
        Response response = Response.builder()
                .status(status)
                .reason("reason")
                .request(request)
                .body(body != null ? body.getBytes(StandardCharsets.UTF_8) : new byte[0])
                .build();
        return FeignException.errorStatus("POST /v1/business-key/derived-keys:wrap", response);
    }
}
