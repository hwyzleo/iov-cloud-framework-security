package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoderRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.support.ParProtoKeyprovAadV1Encoder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PAR-PROTO keyprov AAD profile 权威向量测试（FW-SEC-DSN-CR-020 §7 测试 1/3）。
 * <p>
 * 冻结契约夹具 {@link ParProtoKeyprovAadV1Encoder} 在固定 probe 上下文上的字节输出
 * （权威向量由 VMD PAR-PROTO 联调对齐后替换）；并验证确定性、有界与 fail-closed 注册规则。
 */
class EnvelopeAadVectorTest {

    private static final EnvelopeAadContext PROBE = probe();

    @Test
    void parProtoAad_authorityVector_frozen() {
        byte[] encoded = new ParProtoKeyprovAadV1Encoder().encode(PROBE);
        assertEquals(ParProtoKeyprovAadV1Encoder.AUTHORITY_VECTOR_HEX,
                CanonicalEncoding.hexLower(encoded),
                "PAR-PROTO keyprov AAD 权威向量（长度前缀 + UTF-8）");
    }

    @Test
    void parProtoAad_deterministicForSameContext() {
        ParProtoKeyprovAadV1Encoder encoder = new ParProtoKeyprovAadV1Encoder();
        byte[] first = encoder.encode(PROBE);
        byte[] second = encoder.encode(PROBE);
        assertArrayEquals(first, second, "同上下文字节级一致（重放依赖）");
    }

    @Test
    void parProtoAad_changesWhenContextChanges() {
        ParProtoKeyprovAadV1Encoder encoder = new ParProtoKeyprovAadV1Encoder();
        byte[] base = encoder.encode(PROBE);
        byte[] differentPurpose = encoder.encode(new EnvelopeAadContext(
                PROBE.formatVersion(), PROBE.wrappingSuite(), PROBE.requestId(),
                PROBE.businessDomain(), KeyPurpose.DOWNLINK_AEAD, PROBE.logicalKeyId(),
                PROBE.businessKeyVersion(), PROBE.rootKeyVersion(), PROBE.derivationVersion(),
                PROBE.recipientCertificateDigest()));
        assertTrue(!java.util.Arrays.equals(base, differentPurpose),
                "purpose 变化必须改变 AAD 字节");
    }

    @Test
    void registry_rejectsDuplicateProfile_failClosed() {
        assertThrows(IllegalStateException.class, () -> EnvelopeAadEncoderRegistry.of(
                new ParProtoKeyprovAadV1Encoder(), new ParProtoKeyprovAadV1Encoder()),
                "重复 profile 拒绝注册（FW-SEC-DSN-CR-020 §2）");
    }

    @Test
    void registry_requireUnknownProfile_failClosed() {
        EnvelopeAadEncoderRegistry registry = EnvelopeAadEncoderRegistry.of(
                new ParProtoKeyprovAadV1Encoder());
        assertThrows(IllegalArgumentException.class, () -> registry.require("UNKNOWN_PROFILE"),
                "未注册 profile 不得回退旧 FW AAD/空 AAD");
    }

    @Test
    void registry_rejectsNonDeterministicEncoder_failClosed() {
        assertThrows(IllegalStateException.class, () -> EnvelopeAadEncoderRegistry.of(
                new NonDeterministicEncoder()), "非确定性输出拒绝注册（测试 3）");
    }

    @Test
    void registry_rejectsOversizedEncoder_failClosed() {
        assertThrows(IllegalStateException.class, () -> EnvelopeAadEncoderRegistry.of(
                new OversizedEncoder()), "超限输出拒绝注册（测试 3）");
    }

    @Test
    void registry_rejectsThrowingEncoder_failClosed() {
        assertThrows(IllegalStateException.class, () -> EnvelopeAadEncoderRegistry.of(
                new ThrowingEncoder()), "encode 抛错拒绝注册（测试 3）");
    }

    private static EnvelopeAadContext probe() {
        return new EnvelopeAadContext(
                1,
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                "probe-request",
                "V2C_COMM_ROOT",
                KeyPurpose.UPLINK_AEAD,
                "logical-probe",
                7L,
                3L,
                "v1",
                new byte[32]);
    }

    /** 非确定性 encoder：同上下文两次输出不同。 */
    private static final class NonDeterministicEncoder
            extends ParProtoKeyprovAadV1Encoder {
        private int call;

        @Override
        public byte[] encode(EnvelopeAadContext context) {
            byte[] base = super.encode(context);
            base[0] = (byte) (call++ & 0xFF);
            return base;
        }
    }

    /** 超限 encoder：输出 2 KiB。 */
    private static final class OversizedEncoder extends ParProtoKeyprovAadV1Encoder {
        @Override
        public byte[] encode(EnvelopeAadContext context) {
            return new byte[2048];
        }
    }

    /** 抛错 encoder。 */
    private static final class ThrowingEncoder extends ParProtoKeyprovAadV1Encoder {
        @Override
        public byte[] encode(EnvelopeAadContext context) {
            throw new IllegalStateException("boom");
        }
    }
}
