package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 派生封装跨端 canonical 测试向量（FW-SEC-DSN-CR-014 §3.2/§3.3/§4/§5.2/§8）。
 * <p>
 * 向量值由独立实现（长度前缀 + UTF-8 + SHA-256）计算并冻结，用于锁定
 * {@code kdfInfo} / {@code aadBytes} / {@code envelopeBytesWithoutDigest} /
 * {@code envelopeDigest} / {@code requestDigest} / {@code proofInput} 的字节级契约；
 * 任何本地字符集、字段顺序或长度前缀变化都会使本测试失败。
 */
class DerivedKeyCanonicalVectorTest {

    private static final WrappingSuite SUITE = WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM;
    private static final String LOGICAL_KEY_ID = "logical-v2c-uplink";
    private static final String FINGERPRINT_MIXED = "AB12CD";
    private static final long BUSINESS_KEY_VERSION = 7L;
    private static final long ROOT_KEY_VERSION = 3L;
    private static final String DERIVATION_VERSION = "v1";
    private static final String REQUEST_ID = "req-1";
    private static final String BUSINESS_DOMAIN = "V2C_COMM_ROOT";

    private static final byte[] EPHEMERAL = ephemeralPoint();
    private static final byte[] SALT = bytes(0x10, 32);
    private static final byte[] NONCE = bytes(0xA0, 12);
    private static final byte[] CIPHERTEXT = bytes(0xB0, 32);
    private static final byte[] TAG = bytes(0xC0, 16);
    private static final byte[] KCV = {0x0a, 0x0b, 0x0c};

    private static final String AAD_HEX =
            "00000002763100000022454344485f45535f503235365f484b44465f5348413235365f41455332353647434d"
                    + "000000057265712d310000000d5632435f434f4d4d5f524f4f540000000b55504c494e4b5f41454144"
                    + "000000126c6f676963616c2d7632632d75706c696e6b00000001370000000133000000027631"
                    + "00000006616231326364";
    private static final String AAD_DIGEST_HEX =
            "10981bfbd3bddefa949356fe69e35bc1faa8044a4dbf524ea47cedbbf316aace";
    private static final String ENVELOPE_HEX =
            "00000002763100000022454344485f45535f503235365f484b44465f5348413235365f41455332353647434d"
                    + "0000004104000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324"
                    + "25262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                    + "00000020101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
                    + "0000000276310000000ca0a1a2a3a4a5a6a7a8a9aaab"
                    + "00000020b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                    + "00000010c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                    + "00000085" + AAD_HEX
                    + "00000020" + AAD_DIGEST_HEX
                    + "00000006616231326364"
                    + "000000126c6f676963616c2d7632632d75706c696e6b"
                    + "0000000b55504c494e4b5f41454144"
                    + "0000000137" + "0000000133" + "000000027631"
                    + "000000030a0b0c"
                    + "000000046f702d31";
    private static final String ENVELOPE_DIGEST_HEX =
            "71ebe7d7d6c87699910d0093af8e99df3a149fd500cda64bd90505b4c127c933";
    private static final String KDF_INFO =
            "openiov|keyprov-wrap|v1|req-1|V2C_COMM_ROOT|UPLINK_AEAD|logical-v2c-uplink|7|ab12cd";
    private static final String REQUEST_DIGEST_HEX =
            "dbdb26dd79ffb924b9bdfc3c7d2f2859391a5251b2403b6640f8ee9d8195b543";
    private static final String PROOF_INPUT_HEX =
            "00000058000000166f70656e696f767c6b657970726f762d61636b7c7631000000057265712d31"
                    + "0000000d5632435f434f4d4d5f524f4f540000000b55504c494e4b5f41454144"
                    + "0000000c7368613235363a6b65796964" + "0000000137"
                    + "0000002071ebe7d7d6c87699910d0093af8e99df3a149fd500cda64bd90505b4c127c933"
                    + "000000030a0b0c";

    // ==================== kdfInfo（§3.2） ====================

    @Test
    void kdfInfo_matchesFrozenCrossEndVector() {
        String info = DerivedKeyEnvelopeCanonical.kdfInfo(REQUEST_ID, BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD, LOGICAL_KEY_ID, BUSINESS_KEY_VERSION, FINGERPRINT_MIXED);
        assertEquals(KDF_INFO, info);
    }

    @Test
    void kdfInfo_fingerprintCaseInsensitive_lowercased() {
        String lower = DerivedKeyEnvelopeCanonical.kdfInfo(REQUEST_ID, BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD, LOGICAL_KEY_ID, BUSINESS_KEY_VERSION, "ab12cd");
        assertEquals(KDF_INFO, lower);
    }

    // ==================== AAD / envelope canonical（§3.3/§4） ====================

    @Test
    void aadBytes_matchesFrozenCrossEndVector() {
        assertEquals(AAD_HEX, CanonicalEncoding.hexLower(DerivedKeyEnvelopeCanonical.aadBytes(aad())));
    }

    @Test
    void aadDigest_matchesFrozenCrossEndVector() {
        assertEquals(AAD_DIGEST_HEX,
                CanonicalEncoding.hexLower(DerivedKeyEnvelopeCanonical.aadDigest(aad())));
    }

    @Test
    void envelopeBytesWithoutDigest_matchesFrozenCrossEndVector() {
        assertEquals(ENVELOPE_HEX, CanonicalEncoding.hexLower(
                DerivedKeyEnvelopeCanonical.envelopeBytesWithoutDigest(envelope(null))));
    }

    @Test
    void envelopeDigest_matchesFrozenCrossEndVector() {
        assertEquals(ENVELOPE_DIGEST_HEX, CanonicalEncoding.hexLower(
                DerivedKeyEnvelopeCanonical.envelopeDigest(envelope(null))));
    }

    @Test
    void envelopeBytes_independentOfDeclaredDigest() {
        assertEquals(ENVELOPE_HEX, CanonicalEncoding.hexLower(
                DerivedKeyEnvelopeCanonical.envelopeBytesWithoutDigest(envelope(hex(ENVELOPE_DIGEST_HEX)))));
    }

    @Test
    void verifyEnvelopeDigest_acceptsMatching_rejectsTampered() {
        assertTrue(DerivedKeyEnvelopeCanonical.verifyEnvelopeDigest(envelope(hex(ENVELOPE_DIGEST_HEX))));
        byte[] tampered = hex(ENVELOPE_DIGEST_HEX);
        tampered[0] ^= 0x01;
        assertFalse(DerivedKeyEnvelopeCanonical.verifyEnvelopeDigest(envelope(tampered)));
        assertFalse(DerivedKeyEnvelopeCanonical.verifyEnvelopeDigest(envelope(null)));
    }

    @Test
    void verifyAadDigest_acceptsMatching_rejectsTampered() {
        assertTrue(DerivedKeyEnvelopeCanonical.verifyAadDigest(envelope(hex(ENVELOPE_DIGEST_HEX))));
        DerivedWrappedKeyEnvelopeV1 tampered = new DerivedWrappedKeyEnvelopeV1(
                DerivedWrappedKeyEnvelopeV1.V1, SUITE, EPHEMERAL, SALT,
                DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1, NONCE, CIPHERTEXT, TAG, aadBytes(),
                bytes(0x01, 32), FINGERPRINT_MIXED, LOGICAL_KEY_ID, KeyPurpose.UPLINK_AEAD,
                BUSINESS_KEY_VERSION, ROOT_KEY_VERSION, DERIVATION_VERSION, KCV, "op-1",
                hex(ENVELOPE_DIGEST_HEX));
        assertFalse(DerivedKeyEnvelopeCanonical.verifyAadDigest(tampered));
    }

    // ==================== requestDigest（§5.2） ====================

    @Test
    void requestDigest_matchesFrozenCrossEndVector() {
        byte[] digest = DerivedKeyRequestDigest.requestDigest("iov-framework-security", "V2C_COMM_ROOT",
                "openbao-transit://transit/keys/v2c-comm-root", "latest", DERIVATION_VERSION,
                "sha256:abc", KeyPurpose.UPLINK_AEAD, REQUEST_ID, BUSINESS_KEY_VERSION,
                FINGERPRINT_MIXED, SUITE);
        assertEquals(REQUEST_DIGEST_HEX, CanonicalEncoding.hexLower(digest));
        assertEquals(REQUEST_DIGEST_HEX, DerivedKeyRequestDigest.requestDigestHex(
                "iov-framework-security", "V2C_COMM_ROOT",
                "openbao-transit://transit/keys/v2c-comm-root", "latest", DERIVATION_VERSION,
                "sha256:abc", KeyPurpose.UPLINK_AEAD, REQUEST_ID, BUSINESS_KEY_VERSION,
                FINGERPRINT_MIXED, SUITE));
    }

    @Test
    void requestDigest_changesWhenAnyGovernedFieldChanges() {
        byte[] base = DerivedKeyRequestDigest.requestDigest("caller", "V2C_COMM_ROOT", "ref", "latest",
                "v1", "sha256:abc", KeyPurpose.UPLINK_AEAD, REQUEST_ID, BUSINESS_KEY_VERSION, "fp",
                SUITE);
        byte[] differentPurpose = DerivedKeyRequestDigest.requestDigest("caller", "V2C_COMM_ROOT", "ref",
                "latest", "v1", "sha256:abc", KeyPurpose.DOWNLINK_AEAD, REQUEST_ID,
                BUSINESS_KEY_VERSION, "fp", SUITE);
        byte[] differentCert = DerivedKeyRequestDigest.requestDigest("caller", "V2C_COMM_ROOT", "ref",
                "latest", "v1", "sha256:abc", KeyPurpose.UPLINK_AEAD, REQUEST_ID,
                BUSINESS_KEY_VERSION, "fp2", SUITE);
        byte[] differentVersion = DerivedKeyRequestDigest.requestDigest("caller", "V2C_COMM_ROOT", "ref",
                "latest", "v1", "sha256:abc", KeyPurpose.UPLINK_AEAD, REQUEST_ID, 8L, "fp", SUITE);
        assertFalse(Arrays.equals(base, differentPurpose));
        assertFalse(Arrays.equals(base, differentCert));
        assertFalse(Arrays.equals(base, differentVersion));
    }

    // ==================== import proof（§8） ====================

    @Test
    void proofInput_matchesFrozenCrossEndVector() {
        byte[] proof = ImportProofCanonical.proofInput(REQUEST_ID, BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD, "sha256:keyid", BUSINESS_KEY_VERSION,
                hex(ENVELOPE_DIGEST_HEX), KCV);
        assertEquals(PROOF_INPUT_HEX, CanonicalEncoding.hexLower(proof));
    }

    @Test
    void proofInput_bindsEnvelopeDigestAndKcv() {
        byte[] proof = ImportProofCanonical.proofInput(REQUEST_ID, BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD, "sha256:keyid", BUSINESS_KEY_VERSION,
                hex(ENVELOPE_DIGEST_HEX), KCV);
        byte[] otherKcv = ImportProofCanonical.proofInput(REQUEST_ID, BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD, "sha256:keyid", BUSINESS_KEY_VERSION,
                hex(ENVELOPE_DIGEST_HEX), new byte[]{0x0a, 0x0b, 0x0d});
        assertTrue(ImportProofCanonical.matches(proof, proof));
        assertFalse(ImportProofCanonical.matches(proof, otherKcv));
    }

    // ==================== helpers ====================

    private static EnvelopeAadV1 aad() {
        return new EnvelopeAadV1(DerivedWrappedKeyEnvelopeV1.V1, SUITE, REQUEST_ID, BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD, LOGICAL_KEY_ID, BUSINESS_KEY_VERSION, ROOT_KEY_VERSION,
                DERIVATION_VERSION, FINGERPRINT_MIXED);
    }

    private static DerivedWrappedKeyEnvelopeV1 envelope(byte[] envelopeDigest) {
        return new DerivedWrappedKeyEnvelopeV1(DerivedWrappedKeyEnvelopeV1.V1, SUITE, EPHEMERAL, SALT,
                DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1, NONCE, CIPHERTEXT, TAG, aadBytes(),
                hex(AAD_DIGEST_HEX), FINGERPRINT_MIXED, LOGICAL_KEY_ID, KeyPurpose.UPLINK_AEAD,
                BUSINESS_KEY_VERSION, ROOT_KEY_VERSION, DERIVATION_VERSION, KCV, "op-1",
                envelopeDigest);
    }

    private static byte[] aadBytes() {
        return DerivedKeyEnvelopeCanonical.aadBytes(aad());
    }

    private static byte[] ephemeralPoint() {
        byte[] point = new byte[65];
        point[0] = 0x04;
        for (int i = 0; i < 64; i++) {
            point[1 + i] = (byte) i;
        }
        return point;
    }

    private static byte[] bytes(int start, int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) ((start + i) & 0xFF);
        }
        return out;
    }

    private static byte[] hex(String value) {
        String normalized = value.trim();
        byte[] out = new byte[normalized.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((Character.digit(normalized.charAt(i * 2), 16) << 4)
                    | Character.digit(normalized.charAt(i * 2 + 1), 16));
        }
        return out;
    }

    @Test
    void canonicalEncoding_lengthPrefixAndUtf8() {
        byte[] encoded = CanonicalEncoding.lengthPrefixedUtf8("v1", null, "");
        // "v1" → 2 bytes, null → empty, "" → empty; 3 × int32 前缀
        assertEquals("000000027631" + "00000000" + "00000000",
                CanonicalEncoding.hexLower(encoded));
        assertArrayEquals("v1".getBytes(StandardCharsets.UTF_8), Arrays.copyOfRange(encoded, 4, 6));
    }

    @Test
    void canonicalEncoding_constantTimeEquals_handlesNullAndContent() {
        assertTrue(CanonicalEncoding.constantTimeEquals(null, null));
        assertFalse(CanonicalEncoding.constantTimeEquals(null, new byte[]{1}));
        assertTrue(CanonicalEncoding.constantTimeEquals(new byte[]{1, 2}, new byte[]{1, 2}));
        assertFalse(CanonicalEncoding.constantTimeEquals(new byte[]{1, 2}, new byte[]{1, 3}));
    }
}
