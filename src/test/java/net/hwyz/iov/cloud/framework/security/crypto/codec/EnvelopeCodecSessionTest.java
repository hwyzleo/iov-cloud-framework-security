package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.exception.IntegrityVerificationException;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EnvelopeCodecSessionTest {

    private EnvelopeCodec envelopeCodec;

    @BeforeEach
    void setUp() {
        envelopeCodec = new EnvelopeCodec();
    }

    @Test
    void encodeAndDecode_sessionMode() {
        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId("v2c-comm-root");
        header.setAlg("AES_256_GCM");
        header.setIv(new byte[12]);
        header.setMode(1);
        header.setSalt(new byte[16]);

        byte[] ciphertext = new byte[]{1, 2, 3, 4, 5};

        byte[] encoded = envelopeCodec.encode(header, ciphertext, 1);
        CipherPayload decoded = envelopeCodec.decode(encoded);

        assertNotNull(decoded);
        assertEquals(2, decoded.getVer());
        assertEquals(1, decoded.getMode());
        assertEquals("v2c-comm-root", decoded.getHeader().getKeyId());
        assertEquals("AES_256_GCM", decoded.getHeader().getAlg());
        assertArrayEquals(new byte[16], decoded.getHeader().getSalt());
        assertArrayEquals(new byte[12], decoded.getHeader().getIv());
        assertArrayEquals(ciphertext, decoded.getCiphertext());
    }

    @Test
    void encodeAndDecode_envelopeMode_usesLegacyVersion() {
        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId("test-key-id");
        header.setKeyVersion(1);
        header.setAlg("AES_256_GCM");
        header.setIv(new byte[12]);
        header.setMode(0);

        byte[] ciphertext = new byte[]{1, 2, 3};

        byte[] encoded = envelopeCodec.encode(header, ciphertext);
        CipherPayload decoded = envelopeCodec.decode(encoded);

        assertEquals(1, decoded.getVer());
        assertEquals(0, decoded.getMode());
        assertEquals("test-key-id", decoded.getHeader().getKeyId());
    }

    @Test
    void decode_legacyPayload_backwardCompatible() {
        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId("old-key");
        header.setKeyVersion(3);
        header.setAlg("AES_256_GCM");
        header.setIv(new byte[12]);

        byte[] ciphertext = new byte[]{9, 8, 7};

        byte[] encoded = envelopeCodec.encode(header, ciphertext);

        assertEquals(1, envelopeCodec.decode(encoded).getVer());
        assertEquals(0, envelopeCodec.decode(encoded).getMode());
        assertEquals("old-key", envelopeCodec.decode(encoded).getHeader().getKeyId());
        assertEquals(3, envelopeCodec.decode(encoded).getHeader().getKeyVersion());
    }

    @Test
    void decode_invalidMagic_throws() {
        byte[] invalid = new byte[]{0, 0, 1, 0, 0};
        assertThrows(IntegrityVerificationException.class, () -> envelopeCodec.decode(invalid));
    }

    @Test
    void decode_tooShort_throws() {
        byte[] tooShort = new byte[]{(byte) 0xCF, 0x01};
        assertThrows(IntegrityVerificationException.class, () -> envelopeCodec.decode(tooShort));
    }
}
