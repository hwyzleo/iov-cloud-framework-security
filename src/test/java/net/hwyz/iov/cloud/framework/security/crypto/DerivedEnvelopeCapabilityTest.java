package net.hwyz.iov.cloud.framework.security.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 派生封装信封能力声明测试（FW-SEC-DSN-CR-015 §7）。
 * <p>
 * 本 artifact 只声明 core 结构化视图能力；PAR-PROTO wire mapper 属 VMD 协议 Adapter 范围，
 * 在本 artifact 恒为不支持（bridge 缺失时 wire 下发 capability DOWN，禁止回退私有解析）。
 */
class DerivedEnvelopeCapabilityTest {

    @Test
    void coreDeclaresStructuredEnvelopeViewOnly() {
        assertTrue(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.STRUCTURED_ENVELOPE_VIEW_V1));
        assertEquals(1, DerivedEnvelopeCapability.supported().size());
        assertTrue(DerivedEnvelopeCapability.supported()
                .contains(DerivedEnvelopeCapability.STRUCTURED_ENVELOPE_VIEW_V1));
    }

    @Test
    void parProtoWireCapabilitiesAreNotDeclaredInThisArtifact() {
        assertFalse(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.PAR_PROTO_WIRE_MAPPER_V1));
        assertFalse(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.DETERMINISTIC_PARAMETERS_V1));
        assertFalse(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.WIRE_DIGEST_SELF_CHECK_V1));
    }

    @Test
    void supportsNullIsFalseAndSupportedSetIsImmutable() {
        assertFalse(DerivedEnvelopeCapability.supports(null));
        assertThrows(UnsupportedOperationException.class,
                () -> DerivedEnvelopeCapability.supported().add("X"));
    }
}
