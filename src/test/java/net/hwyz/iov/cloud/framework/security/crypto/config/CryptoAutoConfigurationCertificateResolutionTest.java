package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.CertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateReferenceDirectory;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolutionHealthIndicator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultCertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.FailClosedCertResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.core.env.Environment;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 证书材料解析自动装配 / 强门禁集成测试（FW-SEC-DSN-CR-012 §8）。
 */
class CryptoAutoConfigurationCertificateResolutionTest {

    private final CryptoAutoConfiguration configuration = new CryptoAutoConfiguration();
    private final CryptoProperties properties = new CryptoProperties();
    private final CryptoMetrics cryptoMetrics = mock(CryptoMetrics.class);
    private Environment environment;

    @BeforeEach
    void setUp() {
        environment = mock(Environment.class);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(false);
    }

    @Test
    void disabled_assemblesFailClosedResolver() {
        CertResolver resolver = configuration.certResolver(properties, cryptoMetrics,
                providerOf(null), providerOf(null), providerOf(null), providerOf(null), environment);

        assertTrue(resolver instanceof FailClosedCertResolver);
    }

    @Test
    void enabled_withoutTrustAnchors_failsStartup() {
        properties.getPki().getCertificateResolution().setEnabled(true);

        assertThrows(IllegalStateException.class, () -> configuration.certResolver(
                properties, cryptoMetrics, providerOf(null), providerOf(null),
                providerOf(null), providerOf(null), environment));
    }

    @Test
    void enabled_requireGoodStatus_withoutRevocation_failsStartup() throws Exception {
        properties.getPki().getCertificateResolution().setEnabled(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(
                TestPkiMaterial.pem("CERTIFICATE", TestPkiMaterial.generate().intermediateCert().getEncoded()));

        assertThrows(IllegalStateException.class, () -> configuration.certResolver(
                properties, cryptoMetrics, providerOf(null), providerOf(null),
                providerOf(null), providerOf(null), environment));
    }

    @Test
    void enabled_validConfig_assemblesDefaultResolver() throws Exception {
        properties.getPki().getCertificateResolution().setEnabled(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(
                TestPkiMaterial.pem("CERTIFICATE", TestPkiMaterial.generate().intermediateCert().getEncoded()));
        properties.getPki().getCertificateResolution().getBusinessKeyWrap().setRequireGoodStatus(false);

        CertResolver resolver = configuration.certResolver(properties, cryptoMetrics,
                providerOf(null), providerOf(null), providerOf(null), providerOf(null), environment);

        assertTrue(resolver instanceof DefaultCertResolver);
    }

    @Test
    void enabled_goodStatus_withRevocationEnabled_assemblesDefaultResolver() throws Exception {
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false)).thenReturn(true);
        properties.getPki().getCertificateResolution().setEnabled(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(
                TestPkiMaterial.pem("CERTIFICATE", TestPkiMaterial.generate().intermediateCert().getEncoded()));

        CertResolver resolver = configuration.certResolver(properties, cryptoMetrics,
                providerOf(null), providerOf(null), providerOf(null), providerOf(null), environment);

        assertTrue(resolver instanceof DefaultCertResolver);
    }

    @Test
    void certificateEvidenceValidator_alwaysAvailable() {
        CertificateEvidenceValidator validator = configuration.certificateEvidenceValidator(
                providerOf(null), properties, providerOf(java.time.Clock.systemUTC()));
        assertNotNull(validator);
    }

    @Test
    void healthIndicator_minimalConfigAllowed() {
        // 未启用解析能力时返回 UNKNOWN
        CertificateResolutionHealthIndicator indicator =
                new CertificateResolutionHealthIndicator(properties, false);
        Health health = indicator.health();
        assertEquals(Status.UNKNOWN, health.getStatus());
    }

    @Test
    void healthIndicator_notReadyWhenTrustAnchorsMissing() {
        properties.getPki().getCertificateResolution().setEnabled(true);
        CertificateResolutionHealthIndicator indicator =
                new CertificateResolutionHealthIndicator(properties, false);
        assertEquals(CertificateResolutionHealthIndicator.NOT_READY, indicator.health().getStatus());
    }

    @Test
    void healthIndicator_upWhenValid() throws Exception {
        properties.getPki().getCertificateResolution().setEnabled(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(
                TestPkiMaterial.pem("CERTIFICATE", TestPkiMaterial.generate().intermediateCert().getEncoded()));
        properties.getPki().getCertificateResolution().getBusinessKeyWrap().setRequireGoodStatus(false);
        CertificateResolutionHealthIndicator indicator =
                new CertificateResolutionHealthIndicator(properties, false);
        assertEquals(Status.UP, indicator.health().getStatus());
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
}
