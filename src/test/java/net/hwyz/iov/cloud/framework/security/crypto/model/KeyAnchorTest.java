package net.hwyz.iov.cloud.framework.security.crypto.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * KeyAnchor 规范化与摘要口径测试（FW-SEC-DSN-CR-013 §6/§11）。
 * <p>
 * VIN 规范化：trim → ASCII 大写 → 长度=17 → ISO 3779 字符集（排除 I/O/Q），非法 fail-closed；
 * 摘要为 {@code sha256:<64 hex>}，仅用于完整性/引用，不参与派生；toString 绝不含锚原文。
 */
class KeyAnchorTest {

    private static final String VIN = "LSVAA4187N2123456";

    @Test
    void vin_normalizesTrimAndUppercase() {
        KeyAnchor anchor = KeyAnchor.vin("  " + VIN.toLowerCase() + "  ");

        assertEquals(KeyAnchor.AnchorType.VIN, anchor.type());
        assertEquals(KeyAnchor.VIN_NORMALIZATION_VERSION, anchor.normalizationVersion());
        assertEquals(VIN, anchor.value());
    }

    @Test
    void vin_rejectsWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> KeyAnchor.vin("VIN12345"));
        assertThrows(IllegalArgumentException.class, () -> KeyAnchor.vin("LSVAA4187N21234567"));
    }

    @Test
    void vin_rejectsIllegalCharset() {
        // I/O/Q 不在 ISO 3779 字符集
        assertThrows(IllegalArgumentException.class, () -> KeyAnchor.vin("LSVAA4187N212345I"));
        assertThrows(IllegalArgumentException.class, () -> KeyAnchor.vin("LSVAA4187N212345Q"));
        assertThrows(IllegalArgumentException.class, () -> KeyAnchor.vin("LSVAA4187N21234-6"));
    }

    @Test
    void uid_trimsAndRejectsBlank() {
        KeyAnchor anchor = KeyAnchor.uid("  SN12345  ");

        assertEquals(KeyAnchor.AnchorType.UID, anchor.type());
        assertEquals(KeyAnchor.UID_NORMALIZATION_VERSION, anchor.normalizationVersion());
        assertEquals("SN12345", anchor.value());
        assertThrows(IllegalArgumentException.class, () -> KeyAnchor.uid("   "));
    }

    @Test
    void digest_isSha256HexOverNormalizedValue_andStable() {
        KeyAnchor anchor = KeyAnchor.vin(VIN);

        String digest = anchor.digest();
        assertTrue(digest.startsWith("sha256:"), digest);
        assertEquals("sha256:".length() + 64, digest.length());
        assertEquals(digest, KeyAnchor.vin(VIN).digest());
        // Trim/大小写规范化后同一摘要
        assertEquals(digest, KeyAnchor.vin(" " + VIN.toLowerCase() + " ").digest());
    }

    @Test
    void toString_neverLeaksRawValue() {
        KeyAnchor anchor = KeyAnchor.vin(VIN);

        String text = anchor.toString();
        assertFalse(text.contains(VIN), text);
        assertTrue(text.contains(anchor.digest()), text);
    }
}
