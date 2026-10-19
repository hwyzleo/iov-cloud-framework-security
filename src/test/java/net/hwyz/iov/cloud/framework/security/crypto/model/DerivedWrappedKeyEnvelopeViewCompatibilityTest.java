package net.hwyz.iov.cloud.framework.security.crypto.model;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link DerivedWrappedKey} 结构化视图兼容与一致性测试（FW-SEC-DSN-CR-015 §4.2/§8）。
 * <p>
 * 验证：CR-015 增量演进（新增 {@code envelope} 组件 + 保留旧构造函数 JVM descriptor）、
 * 顶层与视图一致性 fail-closed、{@code envelope == null} 的旧格式读取语义与脱敏输出。
 */
class DerivedWrappedKeyEnvelopeViewCompatibilityTest {

    private static final WrappingSuite SUITE = WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM;
    private static final byte[] ENVELOPE_BYTES = "OPAQUE-CANONICAL-ENVELOPE".getBytes(StandardCharsets.UTF_8);
    private static final byte[] DIGEST = filled(32, 0xD0);
    private static final byte[] KCV = new byte[]{0x0a, 0x0b, 0x0c};

    @Test
    void legacyConstructor_retainedForBinaryCompatibility() throws Exception {
        // 保留旧 9 参构造函数（CR-015 §8：不得直接破坏所有消费者）。
        Constructor<DerivedWrappedKey> legacy = DerivedWrappedKey.class.getDeclaredConstructor(
                String.class, String.class, long.class, String.class, WrappingSuite.class,
                byte[].class, byte[].class, byte[].class, String.class);
        assertNotNull(legacy);
        assertEquals(9, legacy.getParameterCount());
    }

    @Test
    void legacyConstructor_producesEnvelopeNullLegacyResult() {
        DerivedWrappedKey legacy = new DerivedWrappedKey("logical-1", "openbao-derived://ref", 3L, "v1",
                SUITE, ENVELOPE_BYTES.clone(), DIGEST.clone(), KCV.clone(), "op-1");

        assertNull(legacy.envelope(), "旧格式结果的 envelope 必须为 null（不代表 ECDH-ES v1 已就绪）");
        assertArrayEquals(ENVELOPE_BYTES, legacy.envelopeBytes());
    }

    @Test
    void structuredConstructor_acceptsConsistentView() {
        DerivedWrappedKey key = consistent();

        assertNotNull(key.envelope());
        assertEquals("ECDH_ES_P256_V1", key.envelope().envelopeFormat());
        assertEquals(SUITE, key.envelope().wrappingSuite());
        assertArrayEquals(DIGEST, key.envelope().envelopeDigest());
        assertArrayEquals(KCV, key.envelope().keyCheckValue());
    }

    @Test
    void structuredConstructor_rejectsSuiteDivergence() {
        assertThrows(IllegalArgumentException.class, () -> new DerivedWrappedKey(
                "logical-1", "ref", 3L, "v1", WrappingSuite.RSA_OAEP_SHA256, view(), ENVELOPE_BYTES,
                DIGEST, KCV, "op-1"));
    }

    @Test
    void structuredConstructor_rejectsDigestDivergence() {
        assertThrows(IllegalArgumentException.class, () -> new DerivedWrappedKey(
                "logical-1", "ref", 3L, "v1", SUITE, view(), ENVELOPE_BYTES,
                filled(32, 0x01), KCV, "op-1"));
        assertThrows(IllegalArgumentException.class, () -> new DerivedWrappedKey(
                "logical-1", "ref", 3L, "v1", SUITE, view(), ENVELOPE_BYTES, null, KCV, "op-1"));
    }

    @Test
    void structuredConstructor_rejectsKcvDivergence() {
        assertThrows(IllegalArgumentException.class, () -> new DerivedWrappedKey(
                "logical-1", "ref", 3L, "v1", SUITE, view(), ENVELOPE_BYTES, DIGEST, new byte[]{1, 2, 3},
                "op-1"));
    }

    @Test
    void structuredConstructor_rejectsMetadataDivergence() {
        // rootKeyVersion
        assertThrows(IllegalArgumentException.class, () -> new DerivedWrappedKey(
                "logical-1", "ref", 9L, "v1", SUITE, view(), ENVELOPE_BYTES, DIGEST, KCV, "op-1"));
        // derivationVersion
        assertThrows(IllegalArgumentException.class, () -> new DerivedWrappedKey(
                "logical-1", "ref", 3L, "v2", SUITE, view(), ENVELOPE_BYTES, DIGEST, KCV, "op-1"));
        // operationId
        assertThrows(IllegalArgumentException.class, () -> new DerivedWrappedKey(
                "logical-1", "ref", 3L, "v1", SUITE, view(), ENVELOPE_BYTES, DIGEST, KCV, "op-2"));
        // logicalKeyId
        assertThrows(IllegalArgumentException.class, () -> new DerivedWrappedKey(
                "logical-2", "ref", 3L, "v1", SUITE, view(), ENVELOPE_BYTES, DIGEST, KCV, "op-1"));
    }

    @Test
    void equalsAndHashCode_includeStructuredView() {
        DerivedWrappedKey withView = consistent();
        DerivedWrappedKey legacy = new DerivedWrappedKey("logical-1", "ref", 3L, "v1", SUITE,
                ENVELOPE_BYTES, DIGEST, KCV, "op-1");

        assertEquals(withView, consistent());
        assertEquals(withView.hashCode(), consistent().hashCode());
        assertNotEquals(withView, legacy);
    }

    @Test
    void toString_doesNotLeakEnvelopeBytes() {
        DerivedWrappedKey key = consistent();

        String description = key.toString();

        assertFalse(description.contains(new String(ENVELOPE_BYTES, StandardCharsets.UTF_8)));
        assertTrue(description.contains("ECDH_ES_P256_V1/v1"));
    }

    // ==================== helpers ====================

    private static DerivedWrappedKey consistent() {
        return new DerivedWrappedKey("logical-1", "ref", 3L, "v1", SUITE, view(), ENVELOPE_BYTES,
                DIGEST, KCV, "op-1");
    }

    private static EcdhEsP256EnvelopeViewV1 view() {
        byte[] ephemeral = new byte[65];
        ephemeral[0] = 0x04;
        return new EcdhEsP256EnvelopeViewV1(1, SUITE, ephemeral, filled(32, 0x10), "v1",
                filled(12, 0xA0), filled(24, 0xB0), filled(16, 0xC0), filled(8, 0xE0), filled(32, 0x11),
                filled(32, 0x22), "logical-1", KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", "op-1",
                DIGEST, KCV);
    }

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        java.util.Arrays.fill(out, (byte) value);
        return out;
    }
}
