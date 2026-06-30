package net.hwyz.iov.cloud.framework.security.crypto.cipher;

import net.hwyz.iov.cloud.framework.security.crypto.exception.IntegrityVerificationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class AeadCipherTest {

    private AeadCipher aeadCipher;

    @BeforeEach
    void setUp() {
        aeadCipher = new AeadCipher();
    }

    @Test
    void testEncryptAndDecrypt() {
        // Given
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] dek = new byte[32]; // 256-bit key
        new SecureRandom().nextBytes(dek);
        byte[] iv = aeadCipher.generateIv();
        byte[] aad = "test-aad".getBytes();

        // When
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dek, iv, aad);
        byte[] decrypted = aeadCipher.decrypt(ciphertext, dek, iv, aad);

        // Then
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testDecryptWithWrongKey() {
        // Given
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] dek = new byte[32];
        new SecureRandom().nextBytes(dek);
        byte[] wrongDek = new byte[32];
        new SecureRandom().nextBytes(wrongDek);
        byte[] iv = aeadCipher.generateIv();
        byte[] aad = "test-aad".getBytes();

        // When
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dek, iv, aad);

        // Then
        assertThrows(IntegrityVerificationException.class, () -> {
            aeadCipher.decrypt(ciphertext, wrongDek, iv, aad);
        });
    }

    @Test
    void testDecryptWithTamperedCiphertext() {
        // Given
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] dek = new byte[32];
        new SecureRandom().nextBytes(dek);
        byte[] iv = aeadCipher.generateIv();
        byte[] aad = "test-aad".getBytes();

        // When
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dek, iv, aad);
        ciphertext[0] ^= 1; // Tamper with ciphertext

        // Then
        assertThrows(IntegrityVerificationException.class, () -> {
            aeadCipher.decrypt(ciphertext, dek, iv, aad);
        });
    }
}
