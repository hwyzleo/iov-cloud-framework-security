package net.hwyz.iov.cloud.framework.security.crypto;

import feign.FeignException;
import feign.Request;
import feign.Response;
import net.hwyz.iov.cloud.framework.security.crypto.client.FeignKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsFeignClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoAutoConfiguration;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyEnvelopeCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.KeyMaterialModelMismatchException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyCreateRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyMaterialPolicy;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.EvidenceSource;
import net.hwyz.iov.cloud.framework.security.crypto.support.DerivedEnvelopeFixture;
import net.hwyz.iov.cloud.framework.security.crypto.support.EcdhP256;
import net.hwyz.iov.cloud.framework.security.crypto.support.ReferenceDerivedKeyUnwrapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * 根派生封装门面端到端集成测试（FW-SEC-DSN-CR-013 §7.2/§8/§10 集成）。
 * <p>
 * 以真实 {@link FeignKmsClient} + {@link DefaultKeyProvisioningTemplate} +
 * {@link DefaultBusinessKeyMaterialTemplate} + {@link CryptoAutoConfiguration} 装配，
 * 贯通 framework 编排（锚层级校验、证书证据解析、受治理根映射）→ Feign 请求映射 → 响应映射；
 * 并验证材料模型路由 fail-closed（DERIVED_ROOT 不进随机材料门面）。OpenBao 插件侧派生实现与
 * 跨组件真实契约测试属插件仓库/联调范围，不在此单元/集成测试替代。
 */
class DerivedKeyProvisioningContractIntegrationTest {

    private static final String VIN = "LSVAA4187N2123456";

    private CryptoProperties properties;
    private KmsFeignClient kmsFeignClient;
    private CryptoMetrics cryptoMetrics;
    private CertResolver certResolver;
    private KmsClient kmsClient;
    private KeyProvisioningTemplate provisioningTemplate;
    private BusinessKeyMaterialTemplate businessKeyMaterialTemplate;
    private CryptoAutoConfiguration configuration;

    private TestPkiMaterial.Pki pki;

    @BeforeEach
    void setUp() throws Exception {
        properties = new CryptoProperties();
        properties.getKms().setEndpoint("http://openiov-openbao:8200");
        properties.getKms().setProvider("openbao-business-key");
        properties.getProvisioning().setEnabled(true);
        properties.getBusinessKey().setEnabled(true);

        kmsFeignClient = mock(KmsFeignClient.class);
        cryptoMetrics = mock(CryptoMetrics.class);
        certResolver = mock(CertResolver.class);
        configuration = new CryptoAutoConfiguration();

        pki = TestPkiMaterial.generate();
        byte[] leafCertDer = pki.leafCert().getEncoded();
        when(certResolver.resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class)))
                .thenReturn(CertificateEvidenceValidator.fromCertificateDer(
                        leafCertDer, EvidenceSource.PROVIDER_QUERY));

        kmsClient = new FeignKmsClient(properties, kmsFeignClient, cryptoMetrics);
        // 经自动装配 Bean 方法装配：真实 FeignKmsClient + 证书解析组件；DeviceResolver/EvidenceValidator 缺省
        provisioningTemplate = configuration.keyProvisioningTemplate(kmsClient, cryptoMetrics, properties,
                providerOf(null), providerOf(certResolver), providerOf(null));
        businessKeyMaterialTemplate = configuration.businessKeyMaterialTemplate(kmsClient, cryptoMetrics,
                properties, providerOf(certResolver), providerOf(null));
    }

    @Test
    void endToEnd_deriveAndWrap_mapsGovernedRootRequestAndResponse() throws Exception {
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        byte[] businessKey = EcdhP256.randomBytes(32);
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) pki.leafKeyPair().getPublic(), businessKey, "req-1", "V2C_COMM_ROOT",
                KeyPurpose.UPLINK_AEAD, "logical-1", 7L, 3L, "v1",
                fingerprintHex(pki.leafCert().getEncoded()), "op-1",
                "openbao-derived://transit/v2c-comm-root/v1/" + anchor.digest() + "/UPLINK_AEAD"));
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        DerivedWrappedKey result = provisioningTemplate.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor,
                KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate("cert-001"),
                DerivationContext.v1(), "op-1", "idem-1");

        assertNotNull(result);
        assertEquals("logical-1", result.logicalKeyId());
        assertEquals(3, result.rootKeyVersion());
        assertEquals("v1", result.derivationVersion());
        assertEquals("op-1", result.operationId());
        assertArrayEquals(built.envelope().kcv(), result.kcv());
        // framework 权威 canonical bytes 必须与 Provider 信封一致（字节级）。
        assertArrayEquals(DerivedKeyEnvelopeCanonical.envelopeBytesWithoutDigest(built.envelope()),
                result.envelopeBytes());

        // CR-015 §4.1：ECDH-ES v1 成功结果必须携带结构化视图，业务消费者不再解析私有 bytes。
        assertNotNull(result.envelope(), "ECDH-ES v1 结果不得出现 envelope=null");
        assertEquals(EcdhEsP256EnvelopeViewV1.ENVELOPE_FORMAT, result.envelope().envelopeFormat());
        assertEquals(EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1, result.envelope().formatVersion());
        assertEquals(WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, result.envelope().wrappingSuite());
        EcdhEsP256EnvelopeViewV1 view = (EcdhEsP256EnvelopeViewV1) result.envelope();
        assertArrayEquals(built.envelope().ciphertext(), view.ciphertext(),
                "结构化视图 ciphertext 必须等于 wrapped_key");
        assertArrayEquals(built.envelope().aad(), view.canonicalAad());
        assertArrayEquals(built.envelope().aadDigest(), view.aadDigest());
        assertArrayEquals(result.envelopeDigest(), view.envelopeDigest());
        assertArrayEquals(result.kcv(), view.keyCheckValue());
        assertArrayEquals(CanonicalEncoding.hexDecode(built.envelope().recipientCertificateFingerprint()),
                view.recipientCertificateDigest());
        assertEquals("logical-1", view.logicalKeyId());
        assertEquals(7L, view.businessKeyVersion());
        assertTrue(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.STRUCTURED_ENVELOPE_VIEW_V1));
        assertFalse(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.PAR_PROTO_WIRE_MAPPER_V1));

        // 端到端解封：模拟 TBOX SEC/HSM 仅凭信封独立计算 KEK 并校验 KCV。
        byte[] imported = ReferenceDerivedKeyUnwrapper.unwrap(pki.leafKeyPair().getPrivate(), built.envelope());
        assertArrayEquals(businessKey, imported);
        assertArrayEquals(EcdhP256.kcvOf(businessKey), built.envelope().kcv());

        // 请求映射：受治理根由 framework 按 bizType 策略映射，客户端不发送 rootKeyRef；
        // 锚原文（参与派生）与 sha256 摘要（完整性比对）一并上送；套件与幂等请求摘要随请求上送。
        verify(kmsFeignClient).deriveAndWrap(argThat(r ->
                "V2C_COMM_ROOT".equals(r.getBizType())
                        && "v1".equals(r.getDerivationVersion())
                        && r.getAnchor() != null
                        && "VIN".equals(r.getAnchor().getType())
                        && "vin-v1".equals(r.getAnchor().getNormalizationVersion())
                        && VIN.equals(r.getAnchor().getValue())
                        && anchor.digest().equals(r.getAnchor().getDigest())
                        && "UPLINK_AEAD".equals(r.getPurpose())
                        && "ECDH-ES+A256GCM".equals(r.getWrappingSuite())
                        && r.getRequestDigest() != null
                        && r.getRecipient() != null
                        && "DEVICE_CERT_PUBLIC_KEY".equals(r.getRecipient().getMode())
                        && r.getRecipient().getCertificateDer() != null
                        && r.getRecipient().getCertificateDer().length > 0
                        && r.getRecipient().getSha256Fingerprint() != null
                        && "op-1".equals(r.getOperationId())
                        && "idem-1".equals(r.getIdempotencyKey())));
        verify(certResolver).resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class));
        verify(cryptoMetrics).recordProvisioningWrap(anyLong());
    }

    @Test
    void endToEnd_deriveAndWrap_replayIsByteIdentical() throws Exception {
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) pki.leafKeyPair().getPublic(), EcdhP256.randomBytes(32), "req-1",
                "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 7L, 3L, "v1",
                fingerprintHex(pki.leafCert().getEncoded()), "op-1", "openbao-derived://ref"));
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        DerivedWrappedKey first = provisioningTemplate.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor,
                KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate("cert-001"),
                DerivationContext.v1(), "op-1", "idem-1");
        DerivedWrappedKey replay = provisioningTemplate.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor,
                KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate("cert-001"),
                DerivationContext.v1(), "op-1", "idem-1");

        assertArrayEquals(first.envelopeBytes(), replay.envelopeBytes());
        assertArrayEquals(first.envelopeDigest(), replay.envelopeDigest());
        assertEquals(first, replay);
    }

    @Test
    void endToEnd_sameOperationDifferentRequestDigest_conflictsNotRetryable() {
        when(kmsFeignClient.deriveAndWrap(any()))
                .thenThrow(feignException(409, "{\"code\":\"IDEMPOTENCY_CONFLICT\"}"));

        BusinessKeyIdempotencyConflictException ex = assertThrows(
                BusinessKeyIdempotencyConflictException.class, () -> provisioningTemplate.deriveAndWrap(
                        BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD,
                        new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(),
                        "op-1", "idem-1"));
        assertFalse(ex.isRetryable());
    }

    @Test
    void endToEnd_sensitiveMaterialNotLeakedInToString() throws Exception {
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) pki.leafKeyPair().getPublic(), EcdhP256.randomBytes(32), "req-1",
                "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 7L, 3L, "v1",
                fingerprintHex(pki.leafCert().getEncoded()), "op-1", "openbao-derived://ref"));
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());

        DerivedWrappedKey result = provisioningTemplate.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor,
                KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate("cert-001"),
                DerivationContext.v1(), "op-1", "idem-1");

        // 敏感信息扫描：信封/KCV 只输出长度，不展开 bytes（CR-014 §10）。
        String description = result.toString() + "|" + built.envelope();
        assertFalse(description.contains(java.util.Base64.getEncoder()
                .encodeToString(result.envelopeBytes())));
        assertFalse(description.contains(java.util.Base64.getEncoder().encodeToString(result.kcv())));
    }

    @Test
    void endToEnd_uplinkAndDownlink_purposeDomainSeparated() throws Exception {
        DerivedEnvelopeFixture.Built built = DerivedEnvelopeFixture.seal(DerivedEnvelopeFixture.Params.of(
                (ECPublicKey) pki.leafKeyPair().getPublic(), EcdhP256.randomBytes(32), "req-1",
                "V2C_COMM_ROOT", KeyPurpose.UPLINK_AEAD, "logical-1", 1L, 1L, "v1",
                fingerprintHex(pki.leafCert().getEncoded()), "op-1", "openbao-derived://ref"));
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(built.response());
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        RecipientRef recipient = new RecipientRef.DeviceCertificate("cert-001");

        provisioningTemplate.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor, KeyPurpose.UPLINK_AEAD,
                recipient, DerivationContext.v1(), "op-u", "idem-u");
        provisioningTemplate.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor, KeyPurpose.DOWNLINK_AEAD,
                recipient, DerivationContext.v1(), "op-d", "idem-d");

        verify(kmsFeignClient).deriveAndWrap(argThat(r -> "UPLINK_AEAD".equals(r.getPurpose())));
        verify(kmsFeignClient).deriveAndWrap(argThat(r -> "DOWNLINK_AEAD".equals(r.getPurpose())));
    }

    @Test
    void endToEnd_anchorDigestMismatch_provider422_failClosedDependencyUnavailable() {
        when(kmsFeignClient.deriveAndWrap(any()))
                .thenThrow(feignException(422, "{\"code\":\"ANCHOR_DIGEST_MISMATCH\"}"));

        assertThrows(CryptoDependencyUnavailableException.class, () -> provisioningTemplate.deriveAndWrap(
                BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(), "op-1", "idem-1"));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void businessKeyMaterialTemplate_createDerivedRoot_failClosed() {
        assertThrows(KeyMaterialModelMismatchException.class, () -> businessKeyMaterialTemplate.create(
                new BusinessKeyCreateRequest(BizType.V2C_COMM_ROOT,
                        KeyMaterialPolicy.of("AES_256", "256"), "idem-1", null)));
        verify(kmsFeignClient, never()).createBusinessKey(any());
    }

    // ==================== helpers ====================

    private static String fingerprintHex(byte[] certificateDer) {
        return CanonicalEncoding.hexLower(CanonicalEncoding.sha256(certificateDer));
    }

    private static <T> ObjectProvider<T> providerOf(T bean) {
        return new ObjectProvider<>() {
            @Override
            public T getObject() {
                return bean;
            }

            @Override
            public T getObject(Object... args) {
                return bean;
            }

            @Override
            public T getIfAvailable() {
                return bean;
            }

            @Override
            public T getIfUnique() {
                return bean;
            }
        };
    }

    private FeignException feignException(int status, String body) {
        Request request = Request.create(Request.HttpMethod.POST,
                "http://openiov-openbao:8200/v1/business-key/derived-keys:wrap", Collections.emptyMap(),
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
