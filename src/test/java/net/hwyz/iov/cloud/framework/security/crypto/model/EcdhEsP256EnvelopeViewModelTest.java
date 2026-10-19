package net.hwyz.iov.cloud.framework.security.crypto.model;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 结构化信封视图模型测试（FW-SEC-DSN-CR-015 §4.1/§6）。
 * <p>
 * 验证：防御性复制、固定长度校验、业务版本范围、非 ECDH-ES 套件与非 v1 版本 fail-closed、
 * P-256 未压缩点前缀校验、脱敏 {@code toString}。
 */
class EcdhEsP256EnvelopeViewModelTest {

    private static final WrappingSuite SUITE = WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM;
    private static final byte[] SECRET = "SECRET-WRAPPED-KEY-CIPHERTEXT".getBytes(StandardCharsets.UTF_8);

    @Test
    void view_defensiveCopy_isolatesInternalBytes() {
        byte[] ciphertext = SECRET.clone();
        EcdhEsP256EnvelopeViewV1 view = view(ciphertext, 7L, SUITE, EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1);

        // 改写源数组不影响内部
        ciphertext[0] = 0x00;
        assertArrayEquals(SECRET, view.ciphertext());

        // 改写访问器返回数组不影响内部
        view.ciphertext()[0] = 0x7F;
        assertArrayEquals(SECRET, view.ciphertext());
    }

    @Test
    void view_exposesFormatIdentity() {
        EcdhEsP256EnvelopeViewV1 view = view(SECRET.clone(), 7L, SUITE,
                EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1);
        assertEquals("ECDH_ES_P256_V1", view.envelopeFormat());
        assertEquals(1, view.formatVersion());
        assertEquals(SUITE, view.wrappingSuite());
    }

    @Test
    void view_rejectsIllegalFixedLengths() {
        // serverEphemeralPublicKey 非 65
        assertThrows(IllegalArgumentException.class, () -> new EcdhEsP256EnvelopeViewV1(
                1, SUITE, new byte[64], salt(), "v1", nonce(), SECRET.clone(), tag(), aad(),
                digest(), digest(), "logical-1", KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", "op-1",
                digest(), new byte[3]));
        // hkdfSalt 非 32
        assertThrows(IllegalArgumentException.class, () -> new EcdhEsP256EnvelopeViewV1(
                1, SUITE, ephemeral(), new byte[16], "v1", nonce(), SECRET.clone(), tag(), aad(),
                digest(), digest(), "logical-1", KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", "op-1",
                digest(), new byte[3]));
        // nonce 非 12
        assertThrows(IllegalArgumentException.class, () -> new EcdhEsP256EnvelopeViewV1(
                1, SUITE, ephemeral(), salt(), "v1", new byte[8], SECRET.clone(), tag(), aad(),
                digest(), digest(), "logical-1", KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", "op-1",
                digest(), new byte[3]));
        // authenticationTag 非 16
        assertThrows(IllegalArgumentException.class, () -> new EcdhEsP256EnvelopeViewV1(
                1, SUITE, ephemeral(), salt(), "v1", nonce(), SECRET.clone(), new byte[8], aad(),
                digest(), digest(), "logical-1", KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", "op-1",
                digest(), new byte[3]));
        // envelopeDigest 非 32
        assertThrows(IllegalArgumentException.class, () -> new EcdhEsP256EnvelopeViewV1(
                1, SUITE, ephemeral(), salt(), "v1", nonce(), SECRET.clone(), tag(), aad(),
                digest(), digest(), "logical-1", KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", "op-1",
                new byte[16], new byte[3]));
        // KCV 非 3
        assertThrows(IllegalArgumentException.class, () -> new EcdhEsP256EnvelopeViewV1(
                1, SUITE, ephemeral(), salt(), "v1", nonce(), SECRET.clone(), tag(), aad(),
                digest(), digest(), "logical-1", KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", "op-1",
                digest(), new byte[4]));
    }

    @Test
    void view_rejectsCompressedOrMalformedEphemeralPoint() {
        byte[] compressed = ephemeral();
        compressed[0] = 0x02; // SEC1 compressed 前缀，非 v1 允许
        assertThrows(IllegalArgumentException.class, () -> new EcdhEsP256EnvelopeViewV1(
                1, SUITE, compressed, salt(), "v1", nonce(), SECRET.clone(), tag(), aad(),
                digest(), digest(), "logical-1", KeyPurpose.UPLINK_AEAD, 7L, 3L, "v1", "op-1",
                digest(), new byte[3]));
    }

    @Test
    void view_rejectsIllegalBusinessKeyVersionRange() {
        assertThrows(IllegalArgumentException.class,
                () -> view(SECRET.clone(), 0L, SUITE, EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1));
        // Long.MAX_VALUE == 2^63-1 合法
        assertDoesNotThrow(() -> view(SECRET.clone(), Long.MAX_VALUE, SUITE,
                EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1));
    }

    @Test
    void view_rejectsNonEcdhSuiteAndUnknownFormatVersion() {
        assertThrows(IllegalArgumentException.class,
                () -> view(SECRET.clone(), 7L, WrappingSuite.RSA_OAEP_SHA256,
                        EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1));
        assertThrows(IllegalArgumentException.class,
                () -> view(SECRET.clone(), 7L, SUITE, 2));
    }

    @Test
    void view_toString_doesNotLeakBytes() {
        EcdhEsP256EnvelopeViewV1 view = view(SECRET.clone(), 7L, SUITE,
                EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1);

        String description = view.toString();

        assertFalse(description.contains(new String(SECRET, StandardCharsets.UTF_8)));
        assertFalse(description.contains(java.util.Base64.getEncoder().encodeToString(SECRET)));
        assertTrue(description.contains("ciphertext=[" + SECRET.length + " bytes]"));
        assertTrue(description.contains("keyCheckValue=[3 bytes]"));
    }

    @Test
    void view_equalsAndHashCode_compareByteContent() {
        EcdhEsP256EnvelopeViewV1 a = view(SECRET.clone(), 7L, SUITE,
                EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1);
        EcdhEsP256EnvelopeViewV1 b = view(SECRET.clone(), 7L, SUITE,
                EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1);
        EcdhEsP256EnvelopeViewV1 c = view(new byte[]{0x01}, 7L, SUITE,
                EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1);

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
        assertTrue(Arrays.equals(SECRET, a.ciphertext()));
    }

    // ==================== helpers ====================

    private static EcdhEsP256EnvelopeViewV1 view(byte[] ciphertext, long businessKeyVersion,
                                                  WrappingSuite suite, int formatVersion) {
        return new EcdhEsP256EnvelopeViewV1(formatVersion, suite, ephemeral(), salt(), "v1", nonce(),
                ciphertext, tag(), aad(), digest(), digest(), "logical-1", KeyPurpose.UPLINK_AEAD,
                businessKeyVersion, 3L, "v1", "op-1", digest(), new byte[]{0x0a, 0x0b, 0x0c});
    }

    private static byte[] ephemeral() {
        byte[] point = new byte[65];
        point[0] = 0x04;
        for (int i = 0; i < 64; i++) {
            point[1 + i] = (byte) i;
        }
        return point;
    }

    private static byte[] salt() {
        return filled(32, 0x10);
    }

    private static byte[] nonce() {
        return filled(12, 0xA0);
    }

    private static byte[] tag() {
        return filled(16, 0xC0);
    }

    private static byte[] aad() {
        return filled(8, 0xE0);
    }

    private static byte[] digest() {
        return filled(32, 0xD0);
    }

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }
}
