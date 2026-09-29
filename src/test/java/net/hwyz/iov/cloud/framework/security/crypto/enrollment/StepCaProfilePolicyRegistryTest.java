package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileNotAllowedException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * StepCaProfilePolicyRegistry 单元测试（FW-SEC-DSN-CR-008 §7）
 */
class StepCaProfilePolicyRegistryTest {

    @Test
    void resolve_shouldReturnPolicy_forRegisteredProfile() {
        StepCaProfilePolicyRegistry registry = new StepCaProfilePolicyRegistry(Map.of(
                "TBOX_IDENTITY", new StepCaProfilePolicy(
                        "TBOX_IDENTITY", "openiov", "kid-1", Duration.ofDays(365),
                        List.of("EC_P256"), List.of("CLIENT_AUTH"), "TBOX")));

        StepCaProfilePolicy policy = registry.resolve("TBOX_IDENTITY");

        assertEquals("openiov", policy.provisioner());
        assertEquals("kid-1", policy.kid());
        assertEquals(Duration.ofDays(365), policy.maxValidity());
        assertEquals(List.of("EC_P256"), policy.allowedKeyAlgorithms());
        assertEquals(List.of("CLIENT_AUTH"), policy.requiredEku());
        assertEquals("TBOX", policy.subjectRule());
    }

    @Test
    void resolve_shouldRejectUnknownProfile() {
        StepCaProfilePolicyRegistry registry = new StepCaProfilePolicyRegistry(Map.of(
                "TBOX_IDENTITY", new StepCaProfilePolicy(
                        "TBOX_IDENTITY", "openiov", "kid-1", null,
                        List.of(), List.of(), "TBOX")));

        assertThrows(CertificateProfileNotAllowedException.class, () -> registry.resolve("UNKNOWN_PROFILE"));
    }

    @Test
    void resolve_shouldReject_whenNoPoliciesConfigured() {
        StepCaProfilePolicyRegistry registry = new StepCaProfilePolicyRegistry(Map.of());
        assertThrows(CertificateProfileNotAllowedException.class, () -> registry.resolve("ANY"));
        assertTrue(registry.profileNames().isEmpty());
    }
}
