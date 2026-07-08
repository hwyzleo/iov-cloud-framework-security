package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DefaultCryptoTemplateSessionTest {

    private DeviceResolver deviceResolver;
    private KeyCache keyCache;
    private AeadCipher aeadCipher;
    private EnvelopeCodec envelopeCodec;
    private CryptoMetrics cryptoMetrics;
    private KmsClient kmsClient;
    private DefaultCryptoTemplate template;

    @BeforeEach
    void setUp() {
        deviceResolver = mock(DeviceResolver.class);
        keyCache = mock(KeyCache.class);
        aeadCipher = new AeadCipher();
        envelopeCodec = new EnvelopeCodec();
        cryptoMetrics = mock(CryptoMetrics.class);
        kmsClient = mock(KmsClient.class);
        template = new DefaultCryptoTemplate(deviceResolver, keyCache, aeadCipher,
                envelopeCodec, cryptoMetrics, kmsClient);
    }

    @Test
    void sessionEncryptDecrypt_roundTrip() {
        String vin = "VIN12345";
        byte[] plaintext = "Hello SESSION!".getBytes();
        byte[] root = new byte[32];
        java.security.SecureRandom rng = new java.security.SecureRandom();
        rng.nextBytes(root);

        when(kmsClient.deriveSessionRoot("v2c-comm-root", "VIN12345")).thenReturn(root);
        when(kmsClient.deriveSessionRoot("v2c-comm-root", null)).thenReturn(root);

        byte[] ciphertext = template.encrypt(vin, BizType.V2C_COMM_ROOT, plaintext);
        assertNotNull(ciphertext);

        byte[] decrypted = template.decrypt(ciphertext);
        assertArrayEquals(plaintext, decrypted);

        verify(cryptoMetrics).recordSessionEncrypt(anyLong());
        verify(cryptoMetrics).recordSessionDecrypt(anyLong());
    }

    @Test
    void sessionDecrypt_legacyEnvelopePayload_backwardCompatible() {
        byte[] dek = new byte[32];
        new java.security.SecureRandom().nextBytes(dek);

        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId("old-key");
        header.setKeyVersion(1);
        header.setAlg("AES_256_GCM");
        byte[] iv = aeadCipher.generateIv();
        header.setIv(iv);

        byte[] aad = envelopeCodec.encode(header, new byte[0]);
        byte[] plaintext = "legacy data".getBytes();
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dek, iv, aad);
        byte[] payload = envelopeCodec.encode(header, ciphertext);

        net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey dataKey =
                new net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey();
        dataKey.setKeyId("old-key");
        dataKey.setKeyVersion(1);
        dataKey.setDekPlaintext(dek);
        when(keyCache.get("old-key", 1)).thenReturn(dataKey);

        byte[] result = template.decrypt(payload);
        assertArrayEquals(plaintext, result);
        verify(cryptoMetrics).recordDecrypt(anyLong());
    }

    @Test
    void envelopeMode_supportsDataFalse_throws() {
        assertThrows(CryptoException.class,
                () -> template.encrypt("VIN123", BizType.TBOX_DEVICE_ROOT, new byte[]{1}));
    }
}
