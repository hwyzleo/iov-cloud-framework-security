package net.hwyz.iov.cloud.framework.security.crypto.model;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 派生封装模型防御性复制与脱敏测试（FW-SEC-DSN-CR-014 §4/§5.1/§10）。
 * <p>
 * 验证：只读/防御性复制语义（构造与访问均不可越界改写内部 bytes）、
 * {@code toString()} 不回显信封/KCV 内容、无隐式套件推断、不可重试错误语义。
 */
class DerivedKeyEnvelopeModelTest {

    private static final byte[] SECRET = "SECRET-BUSINESS-KEY-MATERIAL".getBytes(StandardCharsets.UTF_8);

    private static DerivedWrappedKey key(byte[] envelopeBytes, byte[] envelopeDigest, byte[] kcv) {
        return new DerivedWrappedKey("logical-1", "openbao-derived://ref", 3L, "v1",
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, envelopeBytes, envelopeDigest, kcv, "op-1");
    }

    @Test
    void derivedWrappedKey_defensiveCopy_isolatesInternalBytes() {
        byte[] envelope = SECRET.clone();
        byte[] digest = new byte[]{1, 2, 3};
        byte[] kcv = new byte[]{4, 5, 6};
        DerivedWrappedKey key = key(envelope, digest, kcv);

        // 改写源数组不影响内部
        envelope[0] = 0x00;
        digest[0] = 0x00;
        kcv[0] = 0x00;
        assertArrayEquals(SECRET, key.envelopeBytes());
        assertArrayEquals(new byte[]{1, 2, 3}, key.envelopeDigest());
        assertArrayEquals(new byte[]{4, 5, 6}, key.kcv());

        // 改写访问器返回数组不影响内部
        key.envelopeBytes()[0] = 0x7F;
        key.envelopeDigest()[0] = 0x7F;
        key.kcv()[0] = 0x7F;
        assertArrayEquals(SECRET, key.envelopeBytes());
        assertArrayEquals(new byte[]{1, 2, 3}, key.envelopeDigest());
        assertArrayEquals(new byte[]{4, 5, 6}, key.kcv());
    }

    @Test
    void derivedWrappedKey_toString_doesNotLeakEnvelopeOrKcv() {
        DerivedWrappedKey key = key(SECRET.clone(), new byte[32], new byte[]{9, 9, 9});

        String description = key.toString();

        assertFalse(description.contains(new String(SECRET, StandardCharsets.UTF_8)),
                "toString 不得回显信封明文");
        assertFalse(description.contains(java.util.Base64.getEncoder().encodeToString(SECRET)),
                "toString 不得回显信封 base64");
        assertTrue(description.contains("[" + SECRET.length + " bytes]"), "toString 以长度脱敏");
    }

    @Test
    void derivedWrappedKey_requiresExplicitWrappingSuite() {
        assertThrows(NullPointerException.class, () -> new DerivedWrappedKey(
                "logical-1", "ref", 1L, "v1", null, SECRET, new byte[32], new byte[3], "op-1"));
    }

    @Test
    void derivedWrappedKey_equalsAndHashCode_compareByteContent() {
        DerivedWrappedKey a = key(SECRET.clone(), new byte[]{1}, new byte[]{2});
        DerivedWrappedKey b = key(SECRET.clone(), new byte[]{1}, new byte[]{2});
        DerivedWrappedKey c = key(new byte[]{9}, new byte[]{1}, new byte[]{2});

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
    }

    // ==================== 信封模型 ====================

    private static DerivedWrappedKeyEnvelopeV1 envelope(byte[] ciphertext) {
        return new DerivedWrappedKeyEnvelopeV1(DerivedWrappedKeyEnvelopeV1.V1,
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, new byte[65], new byte[32],
                DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1, new byte[12], ciphertext, new byte[16],
                new byte[8], new byte[32], "ab12cd", "logical-1", KeyPurpose.UPLINK_AEAD, 7L, 3L,
                "v1", new byte[]{4, 5, 6}, "op-1", new byte[32]);
    }

    @Test
    void envelopeV1_defensiveCopy_isolatesInternalBytes() {
        byte[] ciphertext = SECRET.clone();
        DerivedWrappedKeyEnvelopeV1 envelope = envelope(ciphertext);

        ciphertext[0] = 0x00;
        assertArrayEquals(SECRET, envelope.ciphertext());
        envelope.ciphertext()[0] = 0x7F;
        assertArrayEquals(SECRET, envelope.ciphertext());
        assertTrue(Arrays.equals(SECRET, envelope.ciphertext()));
    }

    @Test
    void envelopeV1_toString_doesNotLeakCiphertext() {
        DerivedWrappedKeyEnvelopeV1 envelope = envelope(SECRET.clone());

        String description = envelope.toString();

        assertFalse(description.contains(new String(SECRET, StandardCharsets.UTF_8)));
        assertTrue(description.contains("ciphertext=[" + SECRET.length + " bytes]"));
    }

    @Test
    void envelopeV1_requiresVersionSuiteAndHkdfContext() {
        assertThrows(NullPointerException.class, () -> new DerivedWrappedKeyEnvelopeV1(
                null, WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, new byte[65], new byte[32],
                "v1", new byte[12], new byte[1], new byte[16], new byte[8], new byte[32], "fp",
                "logical-1", KeyPurpose.UPLINK_AEAD, 1L, 1L, "v1", new byte[3], "op-1", new byte[32]));
    }
}
