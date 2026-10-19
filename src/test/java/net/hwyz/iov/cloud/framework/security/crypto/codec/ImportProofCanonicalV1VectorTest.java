package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 导入证明 canonical {@code proofInputV1} 冻结向量与编码契约测试（FW-SEC-DSN-CR-016 §3/§4）。
 * <p>
 * 该向量为 keyprov-v1 唯一有效的生产 canonical 契约，须与 TBOX-SEC C++ 端逐字节一致；
 * 与 legacy {@link ImportProofCanonical#proofInput} 的嵌套编码<strong>不</strong>可混淆。
 */
class ImportProofCanonicalV1VectorTest {

    private static final String REQUEST_ID = "req-1";
    private static final String BUSINESS_DOMAIN = "V2C_COMM";
    private static final String KEY_ID = "logical-v2c-uplink";
    private static final long BUSINESS_KEY_VERSION = 7L;
    private static final String ENVELOPE_DIGEST_HEX =
            "71ebe7d7d6c87699910d0093af8e99df3a149fd500cda64bd90505b4c127c933";
    private static final String KCV_HEX = "0a0b0c";
    private static final String PROOF_INPUT_V1_HEX =
            "000000166f70656e696f767c6b657970726f762d61636b7c7631000000057265712d31"
                    + "000000085632435f434f4d4d000000010100000020"
                    + "d71ab5437ac14e57c51bb541ab2bad89c3f9a27e6fd8e7d7a7cfef05ad4dacc6"
                    + "000000080000000000000007"
                    + "0000002071ebe7d7d6c87699910d0093af8e99df3a149fd500cda64bd90505b4c127c933"
                    + "000000030a0b0c";

    private static byte[] proofInput(KeyPurpose purpose, String keyId, long version,
                                     String envelopeDigestHex) {
        return ImportProofCanonical.proofInputV1(REQUEST_ID, BUSINESS_DOMAIN, purpose, keyId,
                version, CanonicalEncoding.hexDecode(envelopeDigestHex),
                CanonicalEncoding.hexDecode(KCV_HEX));
    }

    @Test
    void proofInputV1_matchesFrozenCrossEndVector() {
        byte[] input = proofInput(KeyPurpose.UPLINK_AEAD, KEY_ID, BUSINESS_KEY_VERSION,
                ENVELOPE_DIGEST_HEX);
        assertEquals(PROOF_INPUT_V1_HEX, CanonicalEncoding.hexLower(input));
    }

    @Test
    void proofInputV1_downlinkPurposeUsesCanonicalValueTwo() {
        byte[] uplink = proofInput(KeyPurpose.UPLINK_AEAD, KEY_ID, BUSINESS_KEY_VERSION,
                ENVELOPE_DIGEST_HEX);
        byte[] downlink = proofInput(KeyPurpose.DOWNLINK_AEAD, KEY_ID, BUSINESS_KEY_VERSION,
                ENVELOPE_DIGEST_HEX);
        assertNotEquals(CanonicalEncoding.hexLower(uplink), CanonicalEncoding.hexLower(downlink));
        // purpose 段为 length-prefixed varint：00000001 01 / 00000001 02
        assertTrue(CanonicalEncoding.hexLower(downlink).contains("0000000102"));
    }

    @Test
    void proofInputV1_bindsEveryGovernedField() {
        byte[] base = proofInput(KeyPurpose.UPLINK_AEAD, KEY_ID, BUSINESS_KEY_VERSION,
                ENVELOPE_DIGEST_HEX);

        byte[] differentKeyId = proofInput(KeyPurpose.UPLINK_AEAD, "logical-v2c-downlink",
                BUSINESS_KEY_VERSION, ENVELOPE_DIGEST_HEX);
        byte[] differentVersion = proofInput(KeyPurpose.UPLINK_AEAD, KEY_ID, 8L, ENVELOPE_DIGEST_HEX);
        byte[] differentDigest = proofInput(KeyPurpose.UPLINK_AEAD, KEY_ID, BUSINESS_KEY_VERSION,
                "0000000000000000000000000000000000000000000000000000000000000000");

        assertFalse(java.util.Arrays.equals(base, differentKeyId));
        assertFalse(java.util.Arrays.equals(base, differentVersion));
        assertFalse(java.util.Arrays.equals(base, differentDigest));
    }

    @Test
    void businessDomain_allowlistIsExactMatchOnly() {
        assertTrue(ImportProofCanonical.isAllowedBusinessDomainV1("V2C_COMM"));
        // V2C_COMM_ROOT 是根派生标识，不是业务域（FW-SEC-DSN-CR-016 §3/§4.1）
        assertFalse(ImportProofCanonical.isAllowedBusinessDomainV1("V2C_COMM_ROOT"));
        assertFalse(ImportProofCanonical.isAllowedBusinessDomainV1("v2c_comm"));
        assertFalse(ImportProofCanonical.isAllowedBusinessDomainV1(" V2C_COMM"));
        assertFalse(ImportProofCanonical.isAllowedBusinessDomainV1("V2C_COMM "));
        assertFalse(ImportProofCanonical.isAllowedBusinessDomainV1("V2C_COMM_2"));
        assertFalse(ImportProofCanonical.isAllowedBusinessDomainV1(null));
    }

    @Test
    void proofInputV1_rejectsDisallowedBusinessDomain() {
        // 修订后的 CR-016 明确要求拒绝根派生标识 V2C_COMM_ROOT 与旧小写 v2c_comm
        for (String domain : new String[]{"V2C_COMM_ROOT", "v2c_comm", "V2C_COMM_ALIAS", " V2C_COMM"}) {
            assertThrows(IllegalArgumentException.class, () -> ImportProofCanonical.proofInputV1(
                    REQUEST_ID, domain, KeyPurpose.UPLINK_AEAD, KEY_ID,
                    BUSINESS_KEY_VERSION, new byte[32], new byte[3]));
        }
    }

    @Test
    void proofInputV1_rejectsBlankRequestIdAndKeyId() {
        assertThrows(IllegalArgumentException.class, () -> ImportProofCanonical.proofInputV1(
                "  ", BUSINESS_DOMAIN, KeyPurpose.UPLINK_AEAD, KEY_ID, BUSINESS_KEY_VERSION,
                new byte[32], new byte[3]));
        assertThrows(IllegalArgumentException.class, () -> ImportProofCanonical.proofInputV1(
                REQUEST_ID, BUSINESS_DOMAIN, KeyPurpose.UPLINK_AEAD, null, BUSINESS_KEY_VERSION,
                new byte[32], new byte[3]));
    }

    @Test
    void canonicalEncoding_uint64beAndVarintAreLittleSurface() {
        assertEquals("0000000000000007", CanonicalEncoding.hexLower(CanonicalEncoding.uint64be(7L)));
        assertEquals("01", CanonicalEncoding.hexLower(CanonicalEncoding.unsignedVarint(1L)));
        assertEquals("02", CanonicalEncoding.hexLower(CanonicalEncoding.unsignedVarint(2L)));
        assertEquals("80", CanonicalEncoding.hexLower(CanonicalEncoding.unsignedVarint(128L)).substring(0, 2));
        assertThrows(IllegalArgumentException.class, () -> CanonicalEncoding.uint64be(-1L));
        assertThrows(IllegalArgumentException.class, () -> CanonicalEncoding.unsignedVarint(-1L));
    }
}
