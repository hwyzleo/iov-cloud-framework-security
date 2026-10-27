package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * BizType 派生策略注册表测试（FW-SEC-DSN-CR-019 RD-019-3/§8）。
 */
class DerivedKeyPolicyRegistryTest {

    private final DerivedKeyPolicyRegistry registry = new DerivedKeyPolicyRegistry();

    private DerivedKeyCommand command(BizType bizType, KeyPurpose purpose, WrappingSuite suite,
                                      String derivationVersion) {
        return new DerivedKeyCommand(bizType, KeyAnchor.vin("LSVAA4187N2123456"), purpose,
                ValidatedRecipientEvidenceFixtures.evidenceOrThrow(suite),
                DerivationContext.of(derivationVersion),
                new OperationContext("op-1", "idem-1"),
                "req-1", "V2C_COMM");
    }

    @Test
    void v2cUplink_validates() {
        DerivedKeyPolicy policy = registry.validate(
                command(BizType.V2C_COMM_ROOT, KeyPurpose.UPLINK_AEAD,
                        WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, "v1"));
        assertEquals("v2c-comm-root", policy.transitKeyName());
        assertEquals("sha2-256", policy.hmacAlgorithm());
        assertEquals("openiov|v2c", policy.derivationLabel());
    }

    @Test
    void unregisteredBizType_rejected() {
        TransitException ex = assertThrows(TransitException.class, () -> registry.validate(
                command(BizType.IMMO_GROUP_KEY, KeyPurpose.UPLINK_AEAD,
                        WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, "v1")));
        assertEquals(net.hwyz.iov.cloud.framework.security.crypto.exception.TransitReason.DERIVATION_POLICY_INVALID,
                ex.transitReason());
    }

    @Test
    void purposeNotAllowed_rejected() {
        // V2C 首期只允许 UPLINK_AEAD / DOWNLINK_AEAD；缺省 purpose 在命令构造阶段 fail-fast
        assertThrows(NullPointerException.class, () -> new DerivedKeyCommand(
                BizType.V2C_COMM_ROOT, KeyAnchor.vin("LSVAA4187N2123456"), null,
                ValidatedRecipientEvidenceFixtures.evidenceOrThrow(
                        WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM),
                DerivationContext.v1(), new OperationContext("op-1", "idem-1"),
                "req-1", "V2C_COMM"));
    }

    @Test
    void derivationVersionNotAllowed_rejected() {
        assertThrows(TransitException.class, () -> registry.validate(
                command(BizType.V2C_COMM_ROOT, KeyPurpose.UPLINK_AEAD,
                        WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, "v2")));
    }

    @Test
    void wrapSuiteNotAllowed_rejected() {
        assertThrows(TransitException.class, () -> registry.validate(
                command(BizType.V2C_COMM_ROOT, KeyPurpose.UPLINK_AEAD,
                        WrappingSuite.RSA_OAEP_SHA256, "v1")));
    }

    @Test
    void policyFor_unregisteredReturnsNull() {
        assertNull(registry.policyFor(BizType.OTA_VEHICLE_ROOT));
        assertNotNull(registry.policyFor(BizType.V2C_COMM_ROOT));
    }

    @Test
    void validateConfig_consistent_passes() {
        CryptoProperties.Provisioning.DerivedKey.RootPolicy root = new CryptoProperties.Provisioning.DerivedKey.RootPolicy();
        root.setTransitKey("v2c-comm-root");
        root.setHmacAlgorithm("sha2-256");
        root.setPurposes(java.util.List.of("UPLINK_AEAD", "DOWNLINK_AEAD"));
        root.setWrapModes(java.util.List.of("DEVICE_CERT_PUBLIC_KEY"));
        Map<String, Object> roots = new LinkedHashMap<>();
        roots.put("V2C_COMM_ROOT", root);
        DerivedKeyPolicyRegistry.validateConfig("v1", roots, root);
    }

    @Test
    void validateConfig_missingRoot_failsStartup() {
        Map<String, Object> roots = new LinkedHashMap<>();
        assertThrows(IllegalStateException.class,
                () -> DerivedKeyPolicyRegistry.validateConfig("v1", roots, null));
    }

    @Test
    void validateConfig_wrongTransitKey_failsStartup() {
        CryptoProperties.Provisioning.DerivedKey.RootPolicy root = new CryptoProperties.Provisioning.DerivedKey.RootPolicy();
        root.setTransitKey("other-root");
        root.setHmacAlgorithm("sha2-256");
        root.setPurposes(java.util.List.of("UPLINK_AEAD", "DOWNLINK_AEAD"));
        root.setWrapModes(java.util.List.of("DEVICE_CERT_PUBLIC_KEY"));
        Map<String, Object> roots = new LinkedHashMap<>();
        roots.put("V2C_COMM_ROOT", root);
        assertThrows(IllegalStateException.class,
                () -> DerivedKeyPolicyRegistry.validateConfig("v1", roots, root));
    }

    @Test
    void validateConfig_unknownRoot_failsStartup() {
        // 配置不允许登记 allowlist 之外的根（Nacos 不能新增任意 Transit Key）
        CryptoProperties.Provisioning.DerivedKey.RootPolicy v2cRoot = new CryptoProperties.Provisioning.DerivedKey.RootPolicy();
        v2cRoot.setTransitKey("v2c-comm-root");
        v2cRoot.setHmacAlgorithm("sha2-256");
        v2cRoot.setPurposes(java.util.List.of("UPLINK_AEAD", "DOWNLINK_AEAD"));
        v2cRoot.setWrapModes(java.util.List.of("DEVICE_CERT_PUBLIC_KEY"));
        Map<String, Object> roots = new LinkedHashMap<>();
        roots.put("V2C_COMM_ROOT", v2cRoot);
        CryptoProperties.Provisioning.DerivedKey.RootPolicy immo = new CryptoProperties.Provisioning.DerivedKey.RootPolicy();
        immo.setTransitKey("immo-group");
        roots.put("IMMO_GROUP_KEY", immo);
        assertThrows(IllegalStateException.class,
                () -> DerivedKeyPolicyRegistry.validateConfig("v1", roots, v2cRoot));
    }
}
