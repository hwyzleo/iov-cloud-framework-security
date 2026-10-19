package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.FailClosedCertResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * 导入证明验签能力就绪门禁单元测试（FW-SEC-DSN-CR-016 §8）。
 */
class ImportProofReadinessTest {

    private CryptoProperties properties;
    private CertResolver resolver;

    @BeforeEach
    void setUp() {
        properties = new CryptoProperties();
        properties.getImportProof().setEnabled(true);
        // 放宽证书解析强门禁，聚焦就绪判定本身
        properties.getImportProof().getCertificate().setRequireTrustedChain(false);
        properties.getImportProof().getCertificate().setRequireGoodStatus(false);
        resolver = mock(CertResolver.class);
    }

    @Test
    void readyWhenCapabilityAndResolverAvailable() {
        ImportProofReadiness readiness = new ImportProofReadiness(properties, resolver, false);
        assertNull(readiness.notReadyReason());
        assertTrue(readiness.isReady());
        assertDoesNotThrow(readiness::verifyAtStartup);
    }

    @Test
    void notReadyWhenResolverFailClosed() {
        ImportProofReadiness readiness =
                new ImportProofReadiness(properties, new FailClosedCertResolver(), false);
        assertNotNull(readiness.notReadyReason());
        assertTrue(readiness.notReadyReason().contains("fail-closed"));
        assertFalse(readiness.isReady());
    }

    @Test
    void notReadyWhenTrustedChainRequiredButAnchorsMissing() {
        properties.getImportProof().getCertificate().setRequireTrustedChain(true);
        ImportProofReadiness readiness = new ImportProofReadiness(properties, resolver, true);
        assertNotNull(readiness.notReadyReason());
        assertTrue(readiness.notReadyReason().contains("trust-anchors-pem"));
    }

    @Test
    void readyWhenTrustedChainRequiredAndAnchorsConfigured() throws Exception {
        properties.getImportProof().getCertificate().setRequireTrustedChain(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(
                TestPkiMaterial.pem("CERTIFICATE", TestPkiMaterial.generate().intermediateCert().getEncoded()));
        ImportProofReadiness readiness = new ImportProofReadiness(properties, resolver, true);
        assertNull(readiness.notReadyReason());
    }

    @Test
    void notReadyWhenGoodStatusRequiredButRevocationDisabled() {
        properties.getImportProof().getCertificate().setRequireGoodStatus(true);
        ImportProofReadiness readiness = new ImportProofReadiness(properties, resolver, false);
        assertNotNull(readiness.notReadyReason());
        assertTrue(readiness.notReadyReason().contains("revocation.enabled"));
    }

    @Test
    void verifyAtStartupFailsClosedWhenNotReady() {
        properties.getImportProof().getCertificate().setRequireTrustedChain(true);
        ImportProofReadiness readiness = new ImportProofReadiness(properties, resolver, true);
        assertThrows(IllegalStateException.class, readiness::verifyAtStartup);
    }
}
