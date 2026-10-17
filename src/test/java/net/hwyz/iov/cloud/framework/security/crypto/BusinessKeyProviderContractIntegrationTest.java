package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.FeignKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsBusinessKeyProviderReadiness;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsFeignClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsOperationState;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsProviderCapabilities;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoAutoConfiguration;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyCreateRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyMaterialPolicy;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RevocationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * 业务密钥 Provider Adapter 端到端集成测试（FW-SEC-DSN-CR-011 §6/§10 集成）。
 * <p>
 * 以真实 {@link FeignKmsClient} + {@link DefaultBusinessKeyMaterialTemplate} +
 * {@link CryptoAutoConfiguration} 装配，贯通 capability→create→wrap→metadata→revoke→reconcile；
 * 覆盖 capability 未就绪时的 fail-closed。OpenBao 插件与跨组件真实契约测试属插件仓库/联调范围，
 * 不在此单元/集成测试替代。
 */
class BusinessKeyProviderContractIntegrationTest {

    private CryptoProperties properties;
    private KmsFeignClient kmsFeignClient;
    private CryptoMetrics cryptoMetrics;
    private CertResolver certResolver;
    private KmsClient kmsClient;
    private BusinessKeyMaterialTemplate template;
    private CryptoAutoConfiguration configuration;

    private byte[] leafCertDer;

    @BeforeEach
    void setUp() throws Exception {
        properties = new CryptoProperties();
        properties.getKms().setEndpoint("http://openiov-openbao:8200");
        properties.getKms().setProvider("openbao-business-key");
        properties.getKms().getBusinessKey().setEnabled(true);
        properties.getKms().getBusinessKey().setRequireReadyAtStartup(true);

        kmsFeignClient = mock(KmsFeignClient.class);
        cryptoMetrics = mock(CryptoMetrics.class);
        certResolver = mock(CertResolver.class);
        configuration = new CryptoAutoConfiguration();

        leafCertDer = TestPkiMaterial.generate().leafCert().getEncoded();
        when(certResolver.resolveBySerial("cert-001")).thenReturn(leafCertDer);

        kmsClient = new FeignKmsClient(properties, kmsFeignClient, cryptoMetrics);
        template = new DefaultBusinessKeyMaterialTemplate(kmsClient, cryptoMetrics, properties, certResolver);
    }

    @Test
    void endToEnd_capabilityCreateWrapMetadataRevokeReconcile() {
        // 启动门禁：capability READY
        when(kmsFeignClient.getBusinessKeyCapabilities()).thenReturn(capabilitiesResponse());
        KmsBusinessKeyProviderReadiness readiness = configuration.kmsBusinessKeyProviderReadiness(
                kmsClient, properties, cryptoMetrics);
        assertTrue(readiness.isReady());

        // create
        FeignKmsClient.CreateBusinessKeyResponse create = new FeignKmsClient.CreateBusinessKeyResponse();
        create.setKeyId("k-1");
        create.setKmsKeyRef("openbao-business-key://business-key/keys/k-1");
        create.setKmsKeyVersion(1);
        create.setProvider("openbao-business-key");
        create.setAlgorithm("AES_256");
        when(kmsFeignClient.createBusinessKey(any())).thenReturn(create);

        BusinessKeyMaterial material = template.create(new BusinessKeyCreateRequest(
                BizType.V2C_COMM_ROOT, KeyMaterialPolicy.of("AES_256", "256"), "idem-1", null));
        assertEquals("k-1", material.keyId());
        assertEquals("openbao-business-key", material.provider());

        // wrap
        FeignKmsClient.WrapBusinessKeyResponse wrap = new FeignKmsClient.WrapBusinessKeyResponse();
        wrap.setWrapped(new byte[]{7, 7, 7});
        wrap.setKeyId("k-1");
        wrap.setKmsKeyVersion(1);
        wrap.setWrappingAlgorithm("ECDH-ES");
        when(kmsFeignClient.wrapBusinessKey(eq("k-1"), any())).thenReturn(wrap);

        var wrapped = template.wrap(new BusinessKeyRef("k-1", material.kmsKeyRef()),
                new RecipientRef.DeviceCertificate("cert-001"),
                new WrapContext(WrapMode.DEVICE_CERT_PUBLIC_KEY, "idem-w", null));
        assertArrayEquals(new byte[]{7, 7, 7}, wrapped.wrapped());
        verify(kmsFeignClient).wrapBusinessKey(eq("k-1"), argThat(r ->
                "DEVICE_CERT_PUBLIC_KEY".equals(r.getMode())
                        && r.getRecipient().getCertificateDer() != null
                        && r.getRecipient().getCertificateSha256() != null));

        // metadata
        FeignKmsClient.BusinessKeyMetadataResponse metadata = new FeignKmsClient.BusinessKeyMetadataResponse();
        metadata.setKeyId("k-1");
        metadata.setKmsKeyVersion(1);
        metadata.setState("ACTIVE");
        when(kmsFeignClient.getBusinessKeyMetadata("k-1")).thenReturn(metadata);
        assertEquals(CryptoKeyState.ACTIVE, template.getMetadata(
                new BusinessKeyRef("k-1", material.kmsKeyRef())).state());

        // revoke
        FeignKmsClient.RevokeBusinessKeyResponse revoke = new FeignKmsClient.RevokeBusinessKeyResponse();
        revoke.setKeyId("k-1");
        revoke.setState("REVOKED");
        when(kmsFeignClient.revokeBusinessKey(eq("k-1"), any())).thenReturn(revoke);
        assertEquals(CryptoKeyState.REVOKED, template.revoke(
                new BusinessKeyRef("k-1", material.kmsKeyRef()),
                new RevocationRequest("ROTATION", "idem-r")).state());

        // reconcile
        FeignKmsClient.OperationResponse operation = new FeignKmsClient.OperationResponse();
        operation.setState("SUCCEEDED");
        when(kmsFeignClient.getBusinessKeyOperation("op-1")).thenReturn(operation);
        assertEquals(KmsOperationState.SUCCEEDED, kmsClient.getOperation("op-1").state());
    }

    @Test
    void capabilityDown_startupFailsClosed() {
        FeignKmsClient.CapabilitiesResponse down = new FeignKmsClient.CapabilitiesResponse();
        down.setProvider("openbao-business-key");
        down.setApiVersion("v1");
        down.setMount("business-key");
        down.setStorageReady(false);
        down.setMountReady(false);
        when(kmsFeignClient.getBusinessKeyCapabilities()).thenReturn(down);

        assertThrows(IllegalStateException.class, () -> configuration.kmsBusinessKeyProviderReadiness(
                kmsClient, properties, cryptoMetrics));
    }

    @Test
    void providerRouteMissing_createFailsClosedWithoutMisclassifyingNotFound() {
        when(kmsFeignClient.getBusinessKeyCapabilities()).thenReturn(capabilitiesResponse());
        kmsClient.getCapabilities();

        feign.Request request = feign.Request.create(feign.Request.HttpMethod.POST,
                "http://openiov-openbao:8200/v1/business-key/keys",
                java.util.Collections.emptyMap(), new byte[0], java.nio.charset.StandardCharsets.UTF_8);
        feign.Response response = feign.Response.builder().status(404).reason("Not Found").request(request)
                .body("{\"errors\":[\"unsupported path\"]}".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                .build();
        when(kmsFeignClient.createBusinessKey(any()))
                .thenThrow(feign.FeignException.errorStatus("POST", response));

        assertThrows(CryptoDependencyUnavailableException.class, () -> template.create(
                new BusinessKeyCreateRequest(BizType.V2C_COMM_ROOT,
                        KeyMaterialPolicy.of("AES_256", "256"), "idem-1", null)));
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
}
