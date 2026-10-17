package net.hwyz.iov.cloud.framework.security.crypto;

import feign.FeignException;
import feign.Request;
import feign.Response;
import net.hwyz.iov.cloud.framework.security.crypto.client.FeignKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsFeignClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoAutoConfiguration;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.KeyMaterialModelMismatchException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyCreateRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyMaterialPolicy;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.EvidenceSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.nio.charset.StandardCharsets;
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

    private byte[] leafCertDer;

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

        leafCertDer = TestPkiMaterial.generate().leafCert().getEncoded();
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
    void endToEnd_deriveAndWrap_mapsGovernedRootRequestAndResponse() {
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        FeignKmsClient.DerivedWrapResponse response = new FeignKmsClient.DerivedWrapResponse();
        response.setLogicalKeyId("logical-1");
        response.setKmsKeyRef("openbao-derived://transit/v2c-comm-root/v1/" + anchor.digest() + "/UPLINK_AEAD");
        response.setRootKeyVersion(3);
        response.setDerivationVersion("v1");
        response.setWrapped(new byte[]{9, 8, 7});
        response.setWrappingAlgorithm("RSA-OAEP-SHA256");
        response.setKcv("0a0b0c");
        response.setOperationId("op-1");
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(response);

        DerivedWrappedKey result = provisioningTemplate.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor,
                KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate("cert-001"),
                DerivationContext.v1(), "op-1", "idem-1");

        assertNotNull(result);
        assertEquals("logical-1", result.logicalKeyId());
        assertArrayEquals(new byte[]{9, 8, 7}, result.wrapped());
        assertArrayEquals(new byte[]{0x0a, 0x0b, 0x0c}, result.kcv());
        assertEquals(3, result.rootKeyVersion());
        assertEquals("v1", result.derivationVersion());
        assertEquals("op-1", result.operationId());

        // 请求映射：受治理根由 framework 按 bizType 策略映射，客户端不发送 rootKeyRef；
        // 锚原文（参与派生）与 sha256 摘要（完整性比对）一并上送。
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
                        && r.getRecipient().getCertificateDer().length > 0
                        && r.getRecipient().getSha256Fingerprint() != null
                        && "op-1".equals(r.getOperationId())
                        && "idem-1".equals(r.getIdempotencyKey())));
        verify(certResolver).resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class));
        verify(cryptoMetrics).recordProvisioningWrap(anyLong());
    }

    @Test
    void endToEnd_uplinkAndDownlink_purposeDomainSeparated() {
        FeignKmsClient.DerivedWrapResponse response = new FeignKmsClient.DerivedWrapResponse();
        response.setLogicalKeyId("l");
        response.setKmsKeyRef("ref");
        response.setRootKeyVersion(1);
        response.setDerivationVersion("v1");
        response.setWrapped(new byte[]{1});
        response.setWrappingAlgorithm("RSA-OAEP-SHA256");
        response.setKcv("02");
        response.setOperationId("op");
        when(kmsFeignClient.deriveAndWrap(any())).thenReturn(response);
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
