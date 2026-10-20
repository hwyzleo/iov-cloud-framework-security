package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.FailClosedCertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Keyprov 证书 Profile / 完整 ECDH-ES v1 聚合就绪测试（FW-SEC-DSN-CR-017 §9/决策 3）。
 */
class KeyprovReadinessTest {

    private final CryptoProperties properties = new CryptoProperties();
    private CertResolver realResolver;
    private CertResolver failClosedResolver;

    @BeforeEach
    void setUp() {
        realResolver = mock(CertResolver.class);
        failClosedResolver = new FailClosedCertResolver();
        properties.getKeyprov().getCertificateProfile().setRequireTrustedChain(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem("---BEGIN CERTIFICATE---\n...\n");
        properties.getProvisioning().setEnabled(true);
        properties.getImportProof().setEnabled(true);
    }

    private KeyprovReadiness readiness(boolean certificateProfileEnabled, boolean revocationEnabled,
                                       CertResolver resolver) {
        properties.getKeyprov().getCertificateProfile().setEnabled(certificateProfileEnabled);
        return new KeyprovReadiness(properties,
                new TestObjectProvider<TboxDeviceCertificateValidator>(mock(TboxDeviceCertificateValidator.class)),
                new TestObjectProvider<>(Clock.systemUTC()), resolver, revocationEnabled);
    }

    @Test
    void disabled_doesNotDeclareCapability() {
        KeyprovReadiness readiness = readiness(false, true, realResolver);
        assertFalse(readiness.certificateProfileEnabled());
        assertNotNull(readiness.keyprovCertificateReadyReason(), "关闭时不声明 capability");
        assertFalse(readiness.keyprovCertificateReady());
        assertNotNull(readiness.keyprovEcdhEsV1ReadyReason(), "关闭时完整聚合必须 DOWN");
        assertFalse(readiness.keyprovEcdhEsV1Ready());
    }

    @Test
    void ready_whenAssembledAndAllDependenciesPresent() {
        KeyprovReadiness readiness = readiness(true, true, realResolver);
        assertNull(readiness.keyprovCertificateReadyReason(), "KEYPROV_CERTIFICATE_READY 应就绪");
        assertTrue(readiness.keyprovCertificateReady());
        assertNull(readiness.keyprovEcdhEsV1ReadyReason(), "完整聚合应就绪");
        assertTrue(readiness.keyprovEcdhEsV1Ready());
    }

    @Test
    void revocationDisabled_profileReadinessMustBeDown() {
        KeyprovReadiness readiness = readiness(true, false, realResolver);
        assertNotNull(readiness.keyprovCertificateReadyReason(),
                "吊销组件未装配时 Profile readiness 必须 DOWN（不得静默跳过吊销门禁）");
        assertFalse(readiness.keyprovCertificateReady());
        assertFalse(readiness.keyprovEcdhEsV1Ready());
    }

    @Test
    void trustAnchorsMissing_profileReadinessDown() {
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(null);
        KeyprovReadiness readiness = readiness(true, true, realResolver);
        assertNotNull(readiness.keyprovCertificateReadyReason(), "要求受信链但未配置信任锚必须 DOWN");
        assertFalse(readiness.keyprovCertificateReady());
    }

    @Test
    void failClosedResolver_profileReadinessDown() {
        KeyprovReadiness readiness = readiness(true, true, failClosedResolver);
        assertNotNull(readiness.keyprovCertificateReadyReason(), "fail-closed 解析器必须 DOWN");
        assertFalse(readiness.keyprovCertificateReady());
    }

    @Test
    void aggregateRequiresProvisioningAndImportProof() {
        properties.getProvisioning().setEnabled(false);
        KeyprovReadiness readiness = readiness(true, true, realResolver);
        assertTrue(readiness.keyprovCertificateReady(), "KEYPROV_CERTIFICATE_READY 独立就绪");
        assertFalse(readiness.keyprovEcdhEsV1Ready(),
                "完整 KEYPROV_ECDH_ES_V1_READY 必须聚合 provisioning（禁止单边 READY）");

        properties.getProvisioning().setEnabled(true);
        properties.getImportProof().setEnabled(false);
        KeyprovReadiness readiness2 = readiness(true, true, realResolver);
        assertFalse(readiness2.keyprovEcdhEsV1Ready(),
                "完整 KEYPROV_ECDH_ES_V1_READY 必须聚合 import-proof");
    }
}
