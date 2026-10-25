package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.TboxDeviceCertificateValidator;
import net.hwyz.iov.cloud.framework.security.crypto.auth.KmsAuthScope;
import net.hwyz.iov.cloud.framework.security.crypto.auth.OpenBaoTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.OpenBaoAuthenticationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.provider.CertificatePublicKeyWrapper;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCapability;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoderRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.InMemoryOperationResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.provider.OperationResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import net.hwyz.iov.cloud.framework.security.crypto.support.ParProtoKeyprovAadV1Encoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * TransitDerivedKeyCapability 聚合就绪测试（FW-SEC-DSN-CR-019 §10）。
 * <p>
 * 八维聚合：OpenBao health、AppRole、mount/根元数据、HMAC 权限、根类型/版本/不可导出、
 * Certificate Validator、本地 Wrap 自检、BizType 策略；任一缺失 DOWN。
 * business-key mount 404 不再影响 DERIVED_ROOT readiness。
 */
class TransitDerivedKeyReadinessTest {

    private CryptoProperties properties;
    private OpenBaoTokenProvider tokenProvider;
    private TransitHmacClient transitClient;
    private TransitRootMetadataCache metadataCache;
    private TransitDerivedKeyReadiness readiness;
    private EnvelopeAadEncoderRegistry aadRegistry;
    private OperationResultStore resultStore;

    @BeforeEach
    void setUp() {
        properties = new CryptoProperties();
        properties.getProvisioning().getDerivedKey().setDerivationVersion("v1");
        properties.getProvisioning().getDerivedKey().setProvider("openbao-transit-local-wrap");
        // CR-020：新 V2C ECDH-ES 必须配置外部 AAD profile；dev/test 允许 InMemory 支撑 READY
        properties.getProvisioning().getDerivedKey().setAadProfileId(
                ParProtoKeyprovAadV1Encoder.PROFILE_ID);
        properties.getProvisioning().getDerivedKey().getResultStore().setAllowInMemory(true);
        tokenProvider = mock(OpenBaoTokenProvider.class);
        when(tokenProvider.requireValidToken(any())).thenReturn("tok");
        transitClient = mock(TransitHmacClient.class);
        when(transitClient.probeHealth())
                .thenReturn(new TransitSystemHealth(true, false, false));
        when(transitClient.readMetadata(anyString()))
                .thenReturn(new TransitKeyMetadata("v2c-comm-root", "aes256-gcm96",
                        false, true, 3, 3, 1));
        when(transitClient.hmac(anyString(), anyString(), any(), any()))
                .thenReturn(new TransitHmacResult("v1", new byte[32], "v2c-comm-root"));
        metadataCache = new TransitRootMetadataCache(transitClient, Duration.ofMinutes(1));
        aadRegistry = EnvelopeAadEncoderRegistry.of(new ParProtoKeyprovAadV1Encoder());
        resultStore = new InMemoryOperationResultStore();
        readiness = new TransitDerivedKeyReadiness(properties, tokenProvider, transitClient,
                new CertificatePublicKeyWrapper(), new DerivedKeyPolicyRegistry(), metadataCache,
                new TestObjectProvider<>(mock(TboxDeviceCertificateValidator.class)),
                aadRegistry, resultStore);
    }

    @Test
    void allReady_isReady() {
        assertNull(readiness.notReadyReason());
        assertTrue(readiness.isReady());
        DerivedKeyCapability capability = readiness.capability();
        assertTrue(capability.ready());
        assertNull(capability.notReadyReason());
    }

    @Test
    void appRoleFailure_down() {
        when(tokenProvider.requireValidToken(any()))
                .thenThrow(new OpenBaoAuthenticationException("login failed"));
        String reason = readiness.notReadyReason();
        assertTrue(reason != null && reason.startsWith("TRANSIT_AUTH_FAILED"));
        assertFalse(readiness.capability().ready());
    }

    @Test
    void healthSealed_down() {
        when(transitClient.probeHealth()).thenReturn(new TransitSystemHealth(true, true, false));
        assertTrue(readiness.notReadyReason().startsWith("TRANSIT_SEALED"));
        assertFalse(readiness.isReady());
    }

    @Test
    void healthStandby_down() {
        when(transitClient.probeHealth()).thenReturn(new TransitSystemHealth(true, false, true));
        assertTrue(readiness.notReadyReason().startsWith("TRANSIT_UNAVAILABLE"));
    }

    @Test
    void rootExportable_down() {
        when(transitClient.readMetadata(anyString()))
                .thenReturn(new TransitKeyMetadata("v2c-comm-root", "aes256-gcm96",
                        true, true, 3, 3, 1));
        assertTrue(readiness.notReadyReason().startsWith("TRANSIT_ROOT_TYPE_MISMATCH"));
    }

    @Test
    void rootTypeIncompatible_down() {
        when(transitClient.readMetadata(anyString()))
                .thenReturn(new TransitKeyMetadata("v2c-comm-root", "rsa-2048",
                        false, false, 3, 3, 1));
        assertTrue(readiness.notReadyReason().startsWith("TRANSIT_ROOT_TYPE_MISMATCH"));
    }

    @Test
    void hmacProbeForbidden_down() {
        when(transitClient.hmac(anyString(), anyString(), any(), any()))
                .thenThrow(TransitException.hmacForbidden("v2c-comm-root"));
        assertTrue(readiness.notReadyReason().startsWith("TRANSIT_HMAC_FORBIDDEN"));
    }

    @Test
    void hmacProbeUnavailable_down() {
        when(transitClient.hmac(anyString(), anyString(), any(), any()))
                .thenThrow(TransitException.unavailable("probe"));
        assertTrue(readiness.notReadyReason().startsWith("TRANSIT_UNAVAILABLE"));
    }

    @Test
    void certValidatorMissing_down() {
        readiness = new TransitDerivedKeyReadiness(properties, tokenProvider, transitClient,
                new CertificatePublicKeyWrapper(), new DerivedKeyPolicyRegistry(), metadataCache,
                new TestObjectProvider<>(), aadRegistry, resultStore);
        assertTrue(readiness.notReadyReason().startsWith("RECIPIENT_CERTIFICATE_INVALID"));
    }

    @Test
    void aadProfileNotConfigured_down() {
        // CR-020 §6 收紧：新 V2C 未配置 aadProfileId → capability DOWN
        properties.getProvisioning().getDerivedKey().setAadProfileId(null);
        assertTrue(readiness.notReadyReason().startsWith("AAD_PROFILE_NOT_CONFIGURED"));
        assertFalse(readiness.capability().ready());
    }

    @Test
    void aadProfileNotRegistered_down() {
        // 配置了 profile 但 registry 未注册（如 VMD 未提供 encoder）→ fail-closed
        readiness = new TransitDerivedKeyReadiness(properties, tokenProvider, transitClient,
                new CertificatePublicKeyWrapper(), new DerivedKeyPolicyRegistry(), metadataCache,
                new TestObjectProvider<>(mock(TboxDeviceCertificateValidator.class)),
                EnvelopeAadEncoderRegistry.of(), resultStore);
        assertTrue(readiness.notReadyReason().startsWith("AAD_PROFILE_UNAVAILABLE"));
    }

    @Test
    void resultStoreInMemoryNotAllowed_down() {
        // 生产要求：InMemory 未显式 allow-in-memory → EXTERNAL_AAD_PROFILE_V1 DOWN（CR-020 §5）
        properties.getProvisioning().getDerivedKey().getResultStore().setAllowInMemory(false);
        assertTrue(readiness.notReadyReason().startsWith("RESULT_STORE_UNAVAILABLE"));
        assertFalse(readiness.capability().ready());
    }

    @Test
    void resultStoreMissing_down() {
        readiness = new TransitDerivedKeyReadiness(properties, tokenProvider, transitClient,
                new CertificatePublicKeyWrapper(), new DerivedKeyPolicyRegistry(), metadataCache,
                new TestObjectProvider<>(mock(TboxDeviceCertificateValidator.class)),
                aadRegistry, null);
        assertTrue(readiness.notReadyReason().startsWith("RESULT_STORE_UNAVAILABLE"));
    }

    @Test
    void derivationVersionMismatch_down() {
        properties.getProvisioning().getDerivedKey().setDerivationVersion("v2");
        assertTrue(readiness.notReadyReason().startsWith("DERIVATION_POLICY_INVALID"));
    }

    @Test
    void verifyAtStartup_throwsWhenNotReady() {
        when(transitClient.probeHealth()).thenReturn(new TransitSystemHealth(true, true, false));
        assertThrows(IllegalStateException.class, readiness::verifyAtStartup);
    }

    @Test
    void verifyAtStartup_passesWhenReady() {
        readiness.verifyAtStartup(); // 不抛即通过
    }
}
