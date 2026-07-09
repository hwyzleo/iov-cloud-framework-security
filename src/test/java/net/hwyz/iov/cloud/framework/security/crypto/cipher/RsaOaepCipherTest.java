package net.hwyz.iov.cloud.framework.security.crypto.cipher;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData.EncAlg;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

class RsaOaepCipherTest {

    private final RsaOaepCipher cipher = new RsaOaepCipher();

    private byte[] generateRsaPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        return kp.getPublic().getEncoded();
    }

    @Test
    void encrypt_producesValidEnvelopedData() throws Exception {
        byte[] pubKey = generateRsaPublicKey();
        byte[] plaintext = "hello world".getBytes();

        EnvelopedData result = cipher.encrypt(pubKey, plaintext);

        assertNotNull(result);
        assertEquals(EncAlg.RSA_OAEP_AES_256_GCM, result.alg());
        assertNotNull(result.ciphertext());
        assertTrue(result.ciphertext().length > 0);
        assertNotNull(result.wrappedKey());
        assertTrue(result.wrappedKey().length > 0);
        assertNotNull(result.ephemeralPubOrParams());
        assertEquals(12, result.ephemeralPubOrParams().length);
    }

    @Test
    void encrypt_differentPlaintexts_produceDifferentCiphertexts() throws Exception {
        byte[] pubKey = generateRsaPublicKey();

        EnvelopedData r1 = cipher.encrypt(pubKey, "data1".getBytes());
        EnvelopedData r2 = cipher.encrypt(pubKey, "data2".getBytes());

        assertNotEquals(
                java.util.Arrays.toString(r1.ciphertext()),
                java.util.Arrays.toString(r2.ciphertext()));
    }

    @Test
    void encrypt_samePlaintextTwice_produceDifferentCiphertexts() throws Exception {
        byte[] pubKey = generateRsaPublicKey();
        byte[] plaintext = "same data".getBytes();

        EnvelopedData r1 = cipher.encrypt(pubKey, plaintext);
        EnvelopedData r2 = cipher.encrypt(pubKey, plaintext);

        assertNotEquals(
                java.util.Arrays.toString(r1.ciphertext()),
                java.util.Arrays.toString(r2.ciphertext()));
    }

    @Test
    void wrapKey_producesNonEmptyResult() throws Exception {
        byte[] pubKey = generateRsaPublicKey();
        byte[] keyMaterial = new byte[32];
        new java.security.SecureRandom().nextBytes(keyMaterial);

        byte[] wrapped = cipher.wrapKey(pubKey, keyMaterial);

        assertNotNull(wrapped);
        assertTrue(wrapped.length > 0);
    }

    @Test
    void wrapKey_differentKeyMaterials_produceDifferentWrappedKeys() throws Exception {
        byte[] pubKey = generateRsaPublicKey();
        byte[] k1 = new byte[32];
        byte[] k2 = new byte[32];
        new java.security.SecureRandom().nextBytes(k1);
        new java.security.SecureRandom().nextBytes(k2);

        byte[] w1 = cipher.wrapKey(pubKey, k1);
        byte[] w2 = cipher.wrapKey(pubKey, k2);

        assertNotEquals(java.util.Arrays.toString(w1), java.util.Arrays.toString(w2));
    }

    @Test
    void encrypt_emptyPlaintext_succeeds() throws Exception {
        byte[] pubKey = generateRsaPublicKey();

        EnvelopedData result = cipher.encrypt(pubKey, new byte[0]);

        assertNotNull(result);
        assertTrue(result.ciphertext().length > 0);
    }
}
