package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * deriveAndWrap Provider readiness 门禁测试（FW-SEC-DSN-CR-014 §6/§9）。
 * <p>
 * 验证：当 {@code crypto.provisioning.enabled=true} 时，READY 额外要求操作结果存储就绪、
 * envelope v1 与 P-256 ECDH / HKDF-SHA-256 / AES-256-GCM capability；任一不满足即 DOWN，
 * 且<strong>不</strong>允许退回「重新生成新信封」。未启用派生门面时不额外收紧。
 */
class KmsBusinessKeyProviderReadinessDerivedKeyTest {

    private final CryptoProperties properties = new CryptoProperties();
    private final KmsClient kmsClient = mock(KmsClient.class);

    @Test
    void derivedDisabled_baseCapability_alreadyReady_ignoresDerivedGate() {
        properties.getProvisioning().setEnabled(false);
        when(kmsClient.getCapabilities()).thenReturn(caps(true, Set.of(), false));

        KmsBusinessKeyProviderReadiness readiness =
                new KmsBusinessKeyProviderReadiness(kmsClient, properties, null);

        assertTrue(readiness.probe());
    }

    @Test
    void derivedEnabled_fullDerivedCapability_ready() {
        properties.getProvisioning().setEnabled(true);
        when(kmsClient.getCapabilities()).thenReturn(caps(true,
                Set.of(KmsBusinessKeyProviderReadiness.REQUIRED_DERIVED_ENVELOPE_VERSION), true));

        KmsBusinessKeyProviderReadiness readiness =
                new KmsBusinessKeyProviderReadiness(kmsClient, properties, null);

        assertTrue(readiness.probe());
        assertEquals("ready", readiness.getReason());
    }

    @Test
    void derivedEnabled_resultStoreNotReady_down() {
        properties.getProvisioning().setEnabled(true);
        when(kmsClient.getCapabilities()).thenReturn(caps(true,
                Set.of(KmsBusinessKeyProviderReadiness.REQUIRED_DERIVED_ENVELOPE_VERSION), false));

        KmsBusinessKeyProviderReadiness readiness =
                new KmsBusinessKeyProviderReadiness(kmsClient, properties, null);

        assertFalse(readiness.probe());
        assertTrue(readiness.getReason().contains("result store"));
    }

    @Test
    void derivedEnabled_envelopeVersionMissing_down() {
        properties.getProvisioning().setEnabled(true);
        when(kmsClient.getCapabilities()).thenReturn(caps(true, Set.of(), true));

        KmsBusinessKeyProviderReadiness readiness =
                new KmsBusinessKeyProviderReadiness(kmsClient, properties, null);

        assertFalse(readiness.probe());
        assertTrue(readiness.getReason().contains("envelope version"));
    }

    @Test
    void derivedEnabled_algorithmMissing_down() {
        properties.getProvisioning().setEnabled(true);
        when(kmsClient.getCapabilities()).thenReturn(new KmsProviderCapabilities(
                "openbao-business-key", "v1", "business-key", true, true, true,
                Set.of("AES_256"), Set.of(KmsBusinessKeyProviderReadiness.REQUIRED_WRAP_MODE),
                Set.of(KmsBusinessKeyProviderReadiness.REQUIRED_DERIVED_ENVELOPE_VERSION), true));

        KmsBusinessKeyProviderReadiness readiness =
                new KmsBusinessKeyProviderReadiness(kmsClient, properties, null);

        assertFalse(readiness.probe());
        assertTrue(readiness.getReason().contains("algorithm"));
    }

    private static KmsProviderCapabilities caps(boolean storageReady, Set<String> envelopeVersions,
                                                boolean resultStoreReady) {
        return new KmsProviderCapabilities(
                "openbao-business-key", "v1", "business-key", true, storageReady, true,
                Set.of("ECDH_P256", "HKDF_SHA256", "AES_256_GCM"),
                Set.of(KmsBusinessKeyProviderReadiness.REQUIRED_WRAP_MODE),
                envelopeVersions, resultStoreReady);
    }
}
