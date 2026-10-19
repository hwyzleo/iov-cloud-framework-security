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
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeView;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.support.DerivedEnvelopeFixture;
import net.hwyz.iov.cloud.framework.security.crypto.support.EcdhP256;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.PostMapping;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
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
    /** 合法的 32 字节证书指纹（64 hex，CR-015 §4.1 要求结构化视图携带 32 字节证书摘要）。 */
    private static final String FINGERPRINT =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
    void deriveAndWrap_success_mapsRequestAndResponse() throws Exception {
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        KeyPair deviceKeys = EcdhP256.generateKeyPair();
        byte[] businessKey = EcdhP256.randomBytes(32);
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) deviceKeys.getPublic(), businessKey, "req-1", "V2C_COMM_ROOT",
                KeyPurpose.UPLINK_AEAD, "logical-1", 1L, 3L, "v1", FINGERPRINT, "op-1",
                "openbao-derived://transit/v2c-comm-root/v1/" + anchor.digest() + "/UPLINK_AEAD"));
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        DerivedWrappedKey result = kmsClient.deriveAndWrap(
                new KmsDerivedKeyReference("V2C_COMM_ROOT", "openbao-transit://transit/keys/v2c-comm-root"),
                input(),
                KmsRecipient.deviceCertificate("cert-001", new byte[]{1, 2}, "fp1", new byte[]{3, 4}, null),
                new OperationContext("op-1", "idem-1"));

        assertNotNull(result);
        assertEquals("logical-1", result.logicalKeyId());
        assertTrue(result.envelopeBytes() != null && result.envelopeBytes().length > 0);
        assertArrayEquals(built.envelope().kcv(), result.kcv());
        assertArrayEquals(built.envelope().envelopeDigest(), result.envelopeDigest());
        assertEquals(WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, result.wrappingSuite());
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
                        && "ECDH-ES+A256GCM".equals(r.getWrappingSuite())
                        && r.getRequestDigest() != null
                        && "op-1".equals(r.getOperationId())
                        && "idem-1".equals(r.getIdempotencyKey())));
        verify(cryptoMetrics).recordBusinessKeyProviderIdempotency("accepted");
    }

    @Test
    void deriveAndWrap_http409_idempotencyConflict_notRetryable() {
        when(kmsFeignClient.deriveAndWrap(any()))
                .thenThrow(feignException(409, "{\"code\":\"IDEMPOTENCY_CONFLICT\"}"));

        BusinessKeyIdempotencyConflictException ex = assertThrows(
                BusinessKeyIdempotencyConflictException.class, () -> kmsClient.deriveAndWrap(
                        rootRef(), input(), recipient(), operation()));
        assertFalse(ex.isRetryable(), "相同幂等键不同摘要为确定性冲突，不可重试（CR-014 §7.2）");
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
        response.setWrappingSuite(WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM.wireName());
        response.setKcv("zz");
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(response);

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation()));
    }

    // ==================== 信封 v1 响应映射与 fail-closed（FW-SEC-DSN-CR-014 §4/§5） ====================

    @Test
    void deriveAndWrap_unknownWrappingSuite_failsClosed() {
        FeignKmsClient.DerivedWrapResponse response = new FeignKmsClient.DerivedWrapResponse();
        response.setWrappingSuite("MADE-UP-SUITE");
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(response);

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation()));
    }

    @Test
    void deriveAndWrap_aadDigestTampered_failsClosed() throws Exception {
        DerivedEnvelopeFixture.Built built = validSealed();
        built.response().getAad()[0] ^= 0x01;
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation()));
    }

    @Test
    void deriveAndWrap_envelopeDigestTampered_failsClosed() throws Exception {
        DerivedEnvelopeFixture.Built built = validSealed();
        built.response().getEnvelopeDigest()[0] ^= 0x01;
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation()));
    }

    @Test
    void deriveAndWrap_providerEnvelopeBytesDiverge_failsClosed() throws Exception {
        DerivedEnvelopeFixture.Built built = validSealed();
        built.response().getEnvelopeBytes()[0] ^= 0x01;
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation()));
    }

    @Test
    void deriveAndWrap_sameOperation_replayIsByteIdentical() throws Exception {
        DerivedEnvelopeFixture.Built built = validSealed();
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        DerivedWrappedKey first = kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation());
        DerivedWrappedKey replay = kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation());

        assertArrayEquals(first.envelopeBytes(), replay.envelopeBytes());
        assertArrayEquals(first.envelopeDigest(), replay.envelopeDigest());
        assertArrayEquals(first.kcv(), replay.kcv());
        assertEquals(first, replay);
    }

    // ==================== 结构化信封视图投影（FW-SEC-DSN-CR-015 §4.1/§7） ====================

    @Test
    void deriveAndWrap_ecdhEsV1_projectsStructuredEnvelopeView() throws Exception {
        DerivedEnvelopeFixture.Built built = validSealed();
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        DerivedWrappedKey result = kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation());

        DerivedWrappedKeyEnvelopeView view = result.envelope();
        assertNotNull(view, "ECDH-ES v1 成功结果必须携带结构化视图（禁止 envelope == null 回退，CR-015 §7/§8）");
        assertInstanceOf(EcdhEsP256EnvelopeViewV1.class, view);
        assertEquals(EcdhEsP256EnvelopeViewV1.ENVELOPE_FORMAT, view.envelopeFormat());
        assertEquals(EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1, view.formatVersion());
        assertEquals(WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, view.wrappingSuite());
        assertArrayEquals(built.envelope().envelopeDigest(), view.envelopeDigest());
        assertArrayEquals(built.envelope().kcv(), view.keyCheckValue());
        // 顶层与视图 digest/KCV 一致（CR-015 §4.2）
        assertArrayEquals(result.envelopeDigest(), view.envelopeDigest());
        assertArrayEquals(result.kcv(), view.keyCheckValue());

        EcdhEsP256EnvelopeViewV1 v1 = (EcdhEsP256EnvelopeViewV1) view;
        assertArrayEquals(built.envelope().ciphertext(), v1.ciphertext());
        assertArrayEquals(built.envelope().serverEphemeralPublicKey(), v1.serverEphemeralPublicKey());
        assertArrayEquals(built.envelope().hkdfSalt(), v1.hkdfSalt());
        assertArrayEquals(built.envelope().nonce(), v1.nonce());
        assertArrayEquals(built.envelope().authenticationTag(), v1.authenticationTag());
        assertArrayEquals(built.envelope().aad(), v1.canonicalAad());
        assertEquals(1L, v1.businessKeyVersion());
        assertEquals(1L, v1.rootKeyVersion());
        assertEquals("logical-1", v1.logicalKeyId());
        assertEquals("op-1", v1.operationId());
    }

    @Test
    void deriveAndWrap_zeroBusinessKeyVersion_failsClosedAsStructuredView() throws Exception {
        // 业务版本 0 非法（视图要求 1..2^63-1）：声明 STRUCTURED_ENVELOPE_VIEW_V1 后禁止回退私有 bytes
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) EcdhP256.generateKeyPair().getPublic(), EcdhP256.randomBytes(32),
                "req-1", "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 0L, 1L, "v1",
                FINGERPRINT, "op-1", "openbao-derived://ref"));
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> kmsClient.deriveAndWrap(rootRef(), input(), recipient(), operation()));
    }

    // ==================== helpers ====================

    private DerivedEnvelopeFixture.Built validSealed() throws Exception {
        return DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) EcdhP256.generateKeyPair().getPublic(), EcdhP256.randomBytes(32),
                "req-1", "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 1L, 1L, "v1",
                FINGERPRINT, "op-1", "openbao-derived://ref"));
    }

    private KmsDerivedKeyReference rootRef() {
        return new KmsDerivedKeyReference("V2C_COMM_ROOT", "openbao-transit://transit/keys/v2c-comm-root");
    }

    private DerivationInput input() {
        return new DerivationInput(KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, "v1",
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, "req-1", "V2C_COMM_ROOT", 0L);
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
