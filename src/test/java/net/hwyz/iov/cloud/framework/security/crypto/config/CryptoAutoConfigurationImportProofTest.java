package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.ImportProofReadiness;
import net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerificationHealthIndicator;
import net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Status;
import org.springframework.core.env.Environment;

import java.time.Clock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 导入证明验签自动装配 / Health 门禁测试（FW-SEC-DSN-CR-016 §8）。
 */
class CryptoAutoConfigurationImportProofTest {

    private final CryptoAutoConfiguration configuration = new CryptoAutoConfiguration();
    private final CryptoAutoConfiguration.ImportProofHealthConfiguration healthConfiguration =
            new CryptoAutoConfiguration.ImportProofHealthConfiguration();
    private final CryptoProperties properties = new CryptoProperties();
    private final CryptoMetrics cryptoMetrics = mock(CryptoMetrics.class);
    private final CertResolver certResolver = mock(CertResolver.class);
    private Environment environment;

    @BeforeEach
    void setUp() {
        properties.getImportProof().setEnabled(true);
        properties.getImportProof().getCertificate().setRequireTrustedChain(false);
        properties.getImportProof().getCertificate().setRequireGoodStatus(false);
        environment = mock(Environment.class);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(true);
    }

    private ImportProofReadiness readiness() {
        return configuration.importProofReadiness(certResolver, properties, environment);
    }

    private ImportProofVerifier verifier() {
        return configuration.importProofVerifier(certResolver, new TestObjectProvider<>(),
                properties, cryptoMetrics, readiness(), new TestObjectProvider<>(Clock.systemUTC()));
    }

    @Test
    void verifier_assemblesWhenNotRequiringReadinessAtStartup() {
        ImportProofVerifier verifier = verifier();
        assertNotNull(verifier);
        ImportProofVerificationHealthIndicator indicator =
                healthConfiguration.importProofVerificationHealthIndicator(properties,
                        new TestObjectProvider<>(readiness()));
        assertNotNull(indicator);
    }

    @Test
    void verifier_startupGateFailsClosedWhenNotReady() {
        properties.getImportProof().setRequireReadyAtStartup(true);
        properties.getImportProof().getCertificate().setRequireTrustedChain(true);

        assertThrows(IllegalStateException.class, this::verifier);
    }

    @Test
    void verifier_assemblesWhenReadinessRequiredAndReady() throws Exception {
        properties.getImportProof().setRequireReadyAtStartup(true);
        properties.getImportProof().getCertificate().setRequireTrustedChain(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(
                TestPkiMaterial.pem("CERTIFICATE", TestPkiMaterial.generate().intermediateCert().getEncoded()));

        assertNotNull(verifier());
    }

    @Test
    void readiness_reportsSpecificReasonWhenNotReady() {
        properties.getImportProof().getCertificate().setRequireGoodStatus(true);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(false);

        ImportProofReadiness readiness = readiness();
        assertFalse(readiness.isReady());
        assertTrue(readiness.notReadyReason().contains("revocation.enabled"));
    }

    @Test
    void health_disabledReportsDisabled() {
        properties.getImportProof().setEnabled(false);
        ImportProofVerificationHealthIndicator indicator =
                healthConfiguration.importProofVerificationHealthIndicator(properties,
                        new TestObjectProvider<>());

        assertEquals(ImportProofVerificationHealthIndicator.DISABLED, indicator.health().getStatus());
    }

    @Test
    void health_enabledNotReadyReportsNotReady() {
        properties.getImportProof().getCertificate().setRequireTrustedChain(true);
        ImportProofVerificationHealthIndicator indicator =
                healthConfiguration.importProofVerificationHealthIndicator(properties,
                        new TestObjectProvider<>(readiness()));

        assertEquals(ImportProofVerificationHealthIndicator.NOT_READY, indicator.health().getStatus());
    }

    @Test
    void health_enabledAndReadyReportsUp() {
        ImportProofVerificationHealthIndicator indicator =
                healthConfiguration.importProofVerificationHealthIndicator(properties,
                        new TestObjectProvider<>(readiness()));

        assertEquals(Status.UP, indicator.health().getStatus());
        assertEquals(net.hwyz.iov.cloud.framework.security.crypto.ImportProofCapability
                        .IMPORT_PROOF_VERIFY_ECDSA_P256_V1,
                indicator.health().getDetails().get("capabilityId"));
    }
}
