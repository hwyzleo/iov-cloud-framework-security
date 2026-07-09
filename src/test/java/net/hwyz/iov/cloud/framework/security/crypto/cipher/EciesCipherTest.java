package net.hwyz.iov.cloud.framework.security.crypto.cipher;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData.EncAlg;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

class EciesCipherTest {

    private final EciesCipher cipher = new EciesCipher();

    private byte[] generateEcPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        return kp.getPublic().getEncoded();
    }

    @Test
    void encrypt_producesValidEnvelopedData() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        byte[] plaintext = "hello world".getBytes();

        EnvelopedData result = cipher.encrypt(pubKey, plaintext);

        assertNotNull(result);
        assertEquals(EncAlg.ECIES_AES_256_GCM, result.alg());
        assertNotNull(result.ciphertext());
        assertTrue(result.ciphertext().length > 0);
        assertNotNull(result.wrappedKey());
        assertEquals(32, result.wrappedKey().length);
        assertNotNull(result.ephemeralPubOrParams());
        assertTrue(result.ephemeralPubOrParams().length > 0);
    }

    @Test
    void encrypt_differentPlaintexts_produceDifferentCiphertexts() throws Exception {
        byte[] pubKey = generateEcPublicKey();

        EnvelopedData r1 = cipher.encrypt(pubKey, "data1".getBytes());
        EnvelopedData r2 = cipher.encrypt(pubKey, "data2".getBytes());

        assertNotEquals(r1.ciphertext().length, 0);
        assertNotEquals(r2.ciphertext().length, 0);
        assertNotEquals(
                java.util.Arrays.toString(r1.ciphertext()),
                java.util.Arrays.toString(r2.ciphertext()));
    }

    @Test
    void encrypt_samePlaintextTwice_produceDifferentCiphertexts() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        byte[] plaintext = "same data".getBytes();

        EnvelopedData r1 = cipher.encrypt(pubKey, plaintext);
        EnvelopedData r2 = cipher.encrypt(pubKey, plaintext);

        assertNotEquals(
                java.util.Arrays.toString(r1.ciphertext()),
                java.util.Arrays.toString(r2.ciphertext()));
        assertNotEquals(
                java.util.Arrays.toString(r1.ephemeralPubOrParams()),
                java.util.Arrays.toString(r2.ephemeralPubOrParams()));
    }

    @Test
    void wrapKey_produces32ByteKey() throws Exception {
        byte[] pubKey = generateEcPublicKey();

        byte[] wrappedKey = cipher.wrapKey(pubKey);

        assertNotNull(wrappedKey);
        assertEquals(32, wrappedKey.length);
    }

    @Test
    void wrapKey_differentCalls_produceDifferentKeys() throws Exception {
        byte[] pubKey = generateEcPublicKey();

        byte[] k1 = cipher.wrapKey(pubKey);
        byte[] k2 = cipher.wrapKey(pubKey);

        assertNotEquals(java.util.Arrays.toString(k1), java.util.Arrays.toString(k2));
    }

    @Test
    void encrypt_emptyPlaintext_succeeds() throws Exception {
        byte[] pubKey = generateEcPublicKey();

        EnvelopedData result = cipher.encrypt(pubKey, new byte[0]);

        assertNotNull(result);
        assertTrue(result.ciphertext().length > 0);
    }
}
