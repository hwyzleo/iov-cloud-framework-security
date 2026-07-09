package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData;
import net.hwyz.iov.cloud.framework.security.crypto.model.Recipient;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DefaultCertEncryptionTemplateTest {

    private CryptoMetrics cryptoMetrics;
    private CertResolver certResolver;
    private DefaultCertEncryptionTemplate template;

    @BeforeEach
    void setUp() {
        cryptoMetrics = mock(CryptoMetrics.class);
        certResolver = mock(CertResolver.class);
        template = new DefaultCertEncryptionTemplate(cryptoMetrics, certResolver);
    }

    private byte[] generateEcPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        return kp.getPublic().getEncoded();
    }

    private byte[] generateRsaPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        return kp.getPublic().getEncoded();
    }

    // ==================== encryptFor with direct public key ====================

    @Test
    void encryptFor_ecPublicKey_returnsEciesResult() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        Recipient recipient = Recipient.ofPublicKey(pubKey);

        EnvelopedData result = template.encryptFor(recipient, "hello".getBytes());

        assertNotNull(result);
        assertEquals(EnvelopedData.EncAlg.ECIES_AES_256_GCM, result.alg());
        verify(cryptoMetrics).recordCertencEncrypt(anyLong());
    }

    @Test
    void encryptFor_rsaPublicKey_returnsRsaOaepResult() throws Exception {
        byte[] pubKey = generateRsaPublicKey();
        Recipient recipient = Recipient.ofPublicKey(pubKey);

        EnvelopedData result = template.encryptFor(recipient, "hello".getBytes());

        assertNotNull(result);
        assertEquals(EnvelopedData.EncAlg.RSA_OAEP_AES_256_GCM, result.alg());
        verify(cryptoMetrics).recordCertencEncrypt(anyLong());
    }

    @Test
    void encryptFor_differentPlaintexts_produceDifferentCiphertexts() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        Recipient recipient = Recipient.ofPublicKey(pubKey);

        EnvelopedData r1 = template.encryptFor(recipient, "data1".getBytes());
        EnvelopedData r2 = template.encryptFor(recipient, "data2".getBytes());

        assertNotEquals(
                java.util.Arrays.toString(r1.ciphertext()),
                java.util.Arrays.toString(r2.ciphertext()));
    }

    @Test
    void encryptFor_emptyPlaintext_succeeds() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        Recipient recipient = Recipient.ofPublicKey(pubKey);

        EnvelopedData result = template.encryptFor(recipient, new byte[0]);

        assertNotNull(result);
        assertTrue(result.ciphertext().length > 0);
    }

    // ==================== encryptFor with subject-based recipient ====================

    @Test
    void encryptFor_subjectVin_callsCertResolver() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        when(certResolver.resolveByVin("VIN123")).thenReturn(pubKey);

        Recipient recipient = Recipient.ofVehicle("VIN123");
        EnvelopedData result = template.encryptFor(recipient, "hello".getBytes());

        assertNotNull(result);
        assertEquals(EnvelopedData.EncAlg.ECIES_AES_256_GCM, result.alg());
        verify(certResolver).resolveByVin("VIN123");
    }

    @Test
    void encryptFor_subjectDevice_callsCertResolver() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        when(certResolver.resolveByDeviceSn("SN123")).thenReturn(pubKey);

        Recipient recipient = Recipient.ofDevice("SN123");
        EnvelopedData result = template.encryptFor(recipient, "hello".getBytes());

        assertNotNull(result);
        verify(certResolver).resolveByDeviceSn("SN123");
    }

    @Test
    void encryptFor_subjectSerial_callsCertResolver() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        when(certResolver.resolveBySerial("CERT-001")).thenReturn(pubKey);

        Recipient recipient = Recipient.ofSerial("CERT-001");
        EnvelopedData result = template.encryptFor(recipient, "hello".getBytes());

        assertNotNull(result);
        verify(certResolver).resolveBySerial("CERT-001");
    }

    @Test
    void encryptFor_subjectUser_callsCertResolver() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        when(certResolver.resolveByUid("UID123")).thenReturn(pubKey);

        Recipient recipient = Recipient.ofUser("UID123");
        EnvelopedData result = template.encryptFor(recipient, "hello".getBytes());

        assertNotNull(result);
        verify(certResolver).resolveByUid("UID123");
    }

    // ==================== encryptFor null checks ====================

    @Test
    void encryptFor_nullRecipient_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.encryptFor(null, new byte[]{1}));
    }

    @Test
    void encryptFor_nullPlaintext_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.encryptFor(Recipient.ofPublicKey(new byte[]{1}), null));
    }

    // ==================== encryptFor fail-closed ====================

    @Test
    void encryptFor_certResolverThrows_failClosed() {
        when(certResolver.resolveByVin(any()))
                .thenThrow(new net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException("PKI down"));

        assertThrows(CryptoException.class,
                () -> template.encryptFor(Recipient.ofVehicle("VIN123"), new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void encryptFor_invalidPublicKey_failClosed() {
        assertThrows(CryptoException.class,
                () -> template.encryptFor(Recipient.ofPublicKey(new byte[]{0, 1, 2}), new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    // ==================== wrapKeyFor ====================

    @Test
    void wrapKeyFor_ecPublicKey_returnsNonEmpty() throws Exception {
        byte[] pubKey = generateEcPublicKey();
        byte[] keyMaterial = new byte[32];
        new java.security.SecureRandom().nextBytes(keyMaterial);

        byte[] result = template.wrapKeyFor(Recipient.ofPublicKey(pubKey), keyMaterial);

        assertNotNull(result);
        assertTrue(result.length > 0);
        verify(cryptoMetrics).recordCertencWrapKey(anyLong());
    }

    @Test
    void wrapKeyFor_rsaPublicKey_returnsNonEmpty() throws Exception {
        byte[] pubKey = generateRsaPublicKey();
        byte[] keyMaterial = new byte[32];
        new java.security.SecureRandom().nextBytes(keyMaterial);

        byte[] result = template.wrapKeyFor(Recipient.ofPublicKey(pubKey), keyMaterial);

        assertNotNull(result);
        assertTrue(result.length > 0);
        verify(cryptoMetrics).recordCertencWrapKey(anyLong());
    }

    @Test
    void wrapKeyFor_nullRecipient_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.wrapKeyFor(null, new byte[]{1}));
    }

    @Test
    void wrapKeyFor_nullKeyMaterial_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.wrapKeyFor(Recipient.ofPublicKey(new byte[]{1}), null));
    }
}
