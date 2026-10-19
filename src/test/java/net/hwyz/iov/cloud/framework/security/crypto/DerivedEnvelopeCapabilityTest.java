package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 派生封装信封能力声明测试（FW-SEC-DSN-CR-015 §4.3/§7）。
 * <p>
 * 本 artifact 声明 core 结构化视图与公开 canonical verifier 能力；PAR-PROTO wire mapper
 * 属 VMD 协议 Adapter 范围，在本 artifact 恒为不支持（bridge 缺失时 wire 下发 capability DOWN，
 * 禁止回退私有解析）。并验证 {@code CORE_ENVELOPE_DIGEST_VERIFY_V1} 仅在公开
 * {@code verify(DerivedWrappedKeyEnvelopeView)} 可调用时才 READY。
 */
class DerivedEnvelopeCapabilityTest {

    @Test
    void coreDeclaresStructuredViewAndCanonicalVerifierOnly() {
        assertTrue(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.STRUCTURED_ENVELOPE_VIEW_V1));
        assertTrue(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.CORE_ENVELOPE_DIGEST_VERIFY_V1));
        assertEquals(2, DerivedEnvelopeCapability.supported().size());
        assertTrue(DerivedEnvelopeCapability.supported()
                .contains(DerivedEnvelopeCapability.STRUCTURED_ENVELOPE_VIEW_V1));
        assertTrue(DerivedEnvelopeCapability.supported()
                .contains(DerivedEnvelopeCapability.CORE_ENVELOPE_DIGEST_VERIFY_V1));
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
    void coreDigestVerifyReady_whenPublicViewApiAvailable() {
        assertTrue(DerivedEnvelopeCapability.coreDigestVerifyReady());
        assertTrue(DerivedEnvelopeCapability.publicVerifyApiAvailable(
                net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedEnvelopeDigestVerifier.class));
    }

    @Test
    void coreDigestVerify_notReadyWhenApiExposesOnlyPrivateTypeOverload() {
        // 仅有接受私有 DerivedWrappedKeyEnvelopeV1 的内部重载 → CORE_ENVELOPE_DIGEST_VERIFY_V1 不得 READY
        assertFalse(DerivedEnvelopeCapability.publicVerifyApiAvailable(PrivateOnlyVerifier.class));
        assertFalse(DerivedEnvelopeCapability.coreDigestVerifyReady(PrivateOnlyVerifier.class));
    }

    @Test
    void supportsNullIsFalseAndSupportedSetIsImmutable() {
        assertFalse(DerivedEnvelopeCapability.supports(null));
        assertThrows(UnsupportedOperationException.class,
                () -> DerivedEnvelopeCapability.supported().add("X"));
    }

    /** 反例：只暴露私有 envelope 类型的 verifier，不满足公开 API capability。 */
    interface PrivateOnlyVerifier {
        void verify(DerivedWrappedKeyEnvelopeV1 view);
    }
}
