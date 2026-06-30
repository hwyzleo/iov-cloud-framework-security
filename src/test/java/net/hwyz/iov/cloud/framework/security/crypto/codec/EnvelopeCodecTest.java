package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.exception.IntegrityVerificationException;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EnvelopeCodecTest {

    private EnvelopeCodec envelopeCodec;

    @BeforeEach
    void setUp() {
        envelopeCodec = new EnvelopeCodec();
    }

    @Test
    void testEncodeAndDecode() {
        // Given
        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId("test-key-id");
        header.setKeyVersion(1);
        header.setAlg("AES_256_GCM");
        header.setIv(new byte[12]);

        byte[] ciphertext = new byte[]{1, 2, 3, 4, 5};

        // When
        byte[] encoded = envelopeCodec.encode(header, ciphertext);
        CipherPayload decoded = envelopeCodec.decode(encoded);

        // Then
        assertNotNull(decoded);
        assertEquals(1, decoded.getVer());
        assertEquals(header.getKeyId(), decoded.getHeader().getKeyId());
        assertEquals(header.getKeyVersion(), decoded.getHeader().getKeyVersion());
        assertEquals(header.getAlg(), decoded.getHeader().getAlg());
        assertArrayEquals(ciphertext, decoded.getCiphertext());
    }

    @Test
    void testDecodeInvalidMagic() {
        // Given
        byte[] invalidData = new byte[]{0, 0, 1, 0, 0};

        // When & Then
        assertThrows(IntegrityVerificationException.class, () -> {
            envelopeCodec.decode(invalidData);
        });
    }

    @Test
    void testDecodeTooShort() {
        // Given
        byte[] tooShort = new byte[]{(byte) 0xCF, 0x01};

        // When & Then
        assertThrows(IntegrityVerificationException.class, () -> {
            envelopeCodec.decode(tooShort);
        });
    }
}
