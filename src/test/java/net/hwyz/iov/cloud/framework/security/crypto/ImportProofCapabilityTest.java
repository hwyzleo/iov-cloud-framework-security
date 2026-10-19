package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.ImportProofCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 导入证明验签 capability 与静态自检单元测试（FW-SEC-DSN-CR-016 §8）。
 */
class ImportProofCapabilityTest {

    @Test
    void declaresImportProofVerifyCapability() {
        assertTrue(ImportProofCapability.supports(
                ImportProofCapability.IMPORT_PROOF_VERIFY_ECDSA_P256_V1));
        assertEquals(1, ImportProofCapability.supported().size());
        assertFalse(ImportProofCapability.supports("UNKNOWN_CAPABILITY"));
        assertFalse(ImportProofCapability.supports(null));
    }

    @Test
    void publicApiIsCallable() {
        assertTrue(ImportProofCapability.publicApiAvailable());
    }

    @Test
    void canonicalVectorSelfCheckPasses() {
        assertTrue(ImportProofCapability.canonicalVectorReady());
    }

    @Test
    void p1363ProviderSelfCheckPasses() {
        assertTrue(ImportProofCapability.p1363ProviderReady());
    }

    @Test
    void selfCheckReadyWhenAllPreconditionsHold() {
        assertTrue(ImportProofCapability.selfCheckReady());
    }

    @Test
    void domainGuardRejectsRootIdentityAndLegacyVariants() {
        // FW-SEC-DSN-CR-016 §8.1：V2C_COMM_ROOT/小写/别名/trim 变体不得使 capability READY
        assertTrue(ImportProofCapability.domainGuardReady());
        assertTrue(ImportProofCanonical.isAllowedBusinessDomainV1("V2C_COMM"));
        assertFalse(ImportProofCanonical.isAllowedBusinessDomainV1("V2C_COMM_ROOT"));
        assertFalse(ImportProofCanonical.isAllowedBusinessDomainV1("v2c_comm"));
    }

    @Test
    void selfCheckVectorEqualsCanonicalBuilderOutput() {
        byte[] input = ImportProofCanonical.proofInputV1(
                ImportProofCapability.SELF_CHECK_REQUEST_ID,
                ImportProofCapability.SELF_CHECK_BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD,
                ImportProofCapability.SELF_CHECK_KEY_ID,
                ImportProofCapability.SELF_CHECK_BUSINESS_KEY_VERSION,
                CanonicalEncoding.hexDecode(ImportProofCapability.SELF_CHECK_ENVELOPE_DIGEST_HEX),
                CanonicalEncoding.hexDecode(ImportProofCapability.SELF_CHECK_KCV_HEX));
        assertEquals(ImportProofCapability.SELF_CHECK_PROOF_INPUT_HEX,
                CanonicalEncoding.hexLower(input));
    }
}
