package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.DefaultTboxDeviceCertificateValidator;
import net.hwyz.iov.cloud.framework.security.crypto.KeyprovCertificateProfileHealthIndicator;
import net.hwyz.iov.cloud.framework.security.crypto.KeyprovReadiness;
import net.hwyz.iov.cloud.framework.security.crypto.TboxDeviceCertificateValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

import java.time.Clock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 统一 TBOX 设备证书 Profile 自动装配 / Health 门禁测试（FW-SEC-DSN-CR-017 §9/决策 3）。
 */
class CryptoAutoConfigurationKeyprovProfileTest {

    private final CryptoAutoConfiguration configuration = new CryptoAutoConfiguration();
    private final CryptoAutoConfiguration.KeyprovCertificateProfileHealthConfiguration healthConfiguration =
            new CryptoAutoConfiguration.KeyprovCertificateProfileHealthConfiguration();
    private final CryptoProperties properties = new CryptoProperties();
    private final CertResolver certResolver = mock(CertResolver.class);
    private Environment environment;

    @BeforeEach
    void setUp() {
        properties.getKeyprov().getCertificateProfile().setEnabled(true);
        properties.getKeyprov().getCertificateProfile().setRequireTrustedChain(false);
        properties.getKeyprov().getCertificateProfile().setRequireGoodStatus(false);
        properties.getProvisioning().setEnabled(true);
        properties.getImportProof().setEnabled(true);
        environment = mock(Environment.class);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(true);
    }

    private KeyprovReadiness readiness() {
        return configuration.keyprovReadiness(properties,
                new TestObjectProvider<TboxDeviceCertificateValidator>(
                        mock(TboxDeviceCertificateValidator.class)),
                new TestObjectProvider<>(Clock.systemUTC()),
                new TestObjectProvider<>(certResolver), environment);
    }

    private TboxDeviceCertificateValidator validator() {
        return configuration.tboxDeviceCertificateValidator(
                new TestObjectProvider<>(certResolver),
                new TestObjectProvider<>(),
                properties, new TestObjectProvider<>(Clock.systemUTC()),
                new TestObjectProvider<>(readiness()));
    }

    @Test
    void readiness_disabled_reportsDisabledReason() {
        properties.getKeyprov().getCertificateProfile().setEnabled(false);
        KeyprovReadiness readiness = readiness();
        assertNotNull(readiness.keyprovCertificateReadyReason());
        assertTrue(readiness.keyprovCertificateReadyReason().contains("disabled"));
    }

    @Test
    void readiness_revocationDisabled_mustBeDown() {
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(false);
        KeyprovReadiness readiness = readiness();
        assertTrue(readiness.keyprovCertificateReadyReason().contains("revocation.enabled"),
                "吊销组件未装配时 Profile readiness 必须 DOWN");
    }

    @Test
    void validator_assemblesWhenEnabledAndReady() {
        TboxDeviceCertificateValidator validator = validator();
        assertNotNull(validator);
        assertTrue(validator instanceof DefaultTboxDeviceCertificateValidator);
    }

    @Test
    void validator_startupGateFailsClosedWhenNotReady() {
        properties.getKeyprov().getCertificateProfile().setRequireReadyAtStartup(true);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(false);
        assertThrows(IllegalStateException.class, this::validator,
                "require-ready-at-startup=true 且 Profile readiness 未就绪须启动 fail-closed");
    }

    @Test
    void health_disabledReportsDisabled() {
        properties.getKeyprov().getCertificateProfile().setEnabled(false);
        KeyprovCertificateProfileHealthIndicator indicator =
                healthConfiguration.keyprovCertificateProfileHealthIndicator(properties,
                        new TestObjectProvider<>(readiness()));
        assertEquals(KeyprovCertificateProfileHealthIndicator.DISABLED, indicator.health().getStatus());
    }

    @Test
    void health_readyReportsUpWithAggregate() {
        KeyprovCertificateProfileHealthIndicator indicator =
                healthConfiguration.keyprovCertificateProfileHealthIndicator(properties,
                        new TestObjectProvider<>(readiness()));
        assertEquals(org.springframework.boot.actuate.health.Status.UP, indicator.health().getStatus());
    }

    @Test
    void health_aggregateDown_whenProvisioningDisabled() {
        properties.getProvisioning().setEnabled(false);
        KeyprovCertificateProfileHealthIndicator indicator =
                healthConfiguration.keyprovCertificateProfileHealthIndicator(properties,
                        new TestObjectProvider<>(readiness()));
        assertEquals(KeyprovCertificateProfileHealthIndicator.NOT_READY, indicator.health().getStatus(),
                "完整 KEYPROV_ECDH_ES_V1_READY 聚合缺 provisioning 时不得 UP");
    }
}
