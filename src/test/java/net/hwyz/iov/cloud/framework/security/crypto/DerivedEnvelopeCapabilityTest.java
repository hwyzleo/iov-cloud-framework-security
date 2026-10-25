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
        // CR-020：新增 EXTERNAL_AAD_PROFILE_V1 与 AAD_PROFILE[PAR_PROTO_KEYPROV_AAD_V1]（Java 下划线形式）
        assertEquals(4, DerivedEnvelopeCapability.supported().size());
        assertTrue(DerivedEnvelopeCapability.supported()
                .contains(DerivedEnvelopeCapability.STRUCTURED_ENVELOPE_VIEW_V1));
        assertTrue(DerivedEnvelopeCapability.supported()
                .contains(DerivedEnvelopeCapability.CORE_ENVELOPE_DIGEST_VERIFY_V1));
        assertTrue(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.EXTERNAL_AAD_PROFILE_V1));
        assertTrue(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1));
    }

    @Test
    void externalAadProfileWireId_explicitMapping() {
        // Java 常量下划线形式 ↔ 对外规范化 wire ID 显式映射（不依赖 enum.name() 自动转换）
        assertEquals("AAD_PROFILE[PAR_PROTO_KEYPROV_AAD_V1]",
                DerivedEnvelopeCapability.AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1_WIRE_ID);
        assertEquals(DerivedEnvelopeCapability.AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1_WIRE_ID,
                DerivedEnvelopeCapability.wireId(
                        DerivedEnvelopeCapability.AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1));
        assertEquals(DerivedEnvelopeCapability.STRUCTURED_ENVELOPE_VIEW_V1,
                DerivedEnvelopeCapability.wireId(
                        DerivedEnvelopeCapability.STRUCTURED_ENVELOPE_VIEW_V1));
        // supports 接受 wire 形式
        assertTrue(DerivedEnvelopeCapability.supports(
                DerivedEnvelopeCapability.AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1_WIRE_ID));
    }

    @Test
    void externalAadProfileReady_requiresProfileAndResultStore() {
        net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoderRegistry registry =
                net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoderRegistry.of(
                        new net.hwyz.iov.cloud.framework.security.crypto.support
                                .ParProtoKeyprovAadV1Encoder());
        net.hwyz.iov.cloud.framework.security.crypto.provider.OperationResultStore store =
                new net.hwyz.iov.cloud.framework.security.crypto.provider.InMemoryOperationResultStore();
        String profileId = net.hwyz.iov.cloud.framework.security.crypto.support
                .ParProtoKeyprovAadV1Encoder.PROFILE_ID;

        // 全就绪（dev/test allow-in-memory）
        assertNull(DerivedEnvelopeCapability.externalAadProfileReadyReason(
                registry, profileId, store, true));
        assertTrue(DerivedEnvelopeCapability.externalAadProfileReady(
                registry, profileId, store, true));
        // 未配置 profile
        assertNotNull(DerivedEnvelopeCapability.externalAadProfileReadyReason(
                registry, null, store, true));
        // profile 未注册
        assertNotNull(DerivedEnvelopeCapability.externalAadProfileReadyReason(
                registry, "UNKNOWN", store, true));
        // 结果存储缺失
        assertNotNull(DerivedEnvelopeCapability.externalAadProfileReadyReason(
                registry, profileId, null, true));
        // InMemory 未允许 → 生产 DOWN
        assertNotNull(DerivedEnvelopeCapability.externalAadProfileReadyReason(
                registry, profileId, store, false));
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
