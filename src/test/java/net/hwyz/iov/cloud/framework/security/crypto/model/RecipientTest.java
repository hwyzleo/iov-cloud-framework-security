package net.hwyz.iov.cloud.framework.security.crypto.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RecipientTest {

    @Test
    void ofCert_createsCertRecipient() {
        byte[] certDer = new byte[]{1, 2, 3};
        Recipient r = Recipient.ofCert(certDer);
        assertInstanceOf(Recipient.CertRecipient.class, r);
        assertArrayEquals(certDer, ((Recipient.CertRecipient) r).certDer());
    }

    @Test
    void ofPublicKey_createsPublicKeyRecipient() {
        byte[] spki = new byte[]{4, 5, 6};
        Recipient r = Recipient.ofPublicKey(spki);
        assertInstanceOf(Recipient.PublicKeyRecipient.class, r);
        assertArrayEquals(spki, ((Recipient.PublicKeyRecipient) r).spki());
    }

    @Test
    void ofVehicle_createsSubjectRecipientWithVin() {
        Recipient r = Recipient.ofVehicle("VIN123");
        assertInstanceOf(Recipient.SubjectRecipient.class, r);
        Recipient.SubjectRecipient sr = (Recipient.SubjectRecipient) r;
        assertEquals(Recipient.SubjectType.VIN, sr.type());
        assertEquals("VIN123", sr.value());
    }

    @Test
    void ofDevice_createsSubjectRecipientWithDevice() {
        Recipient r = Recipient.ofDevice("SN123");
        Recipient.SubjectRecipient sr = (Recipient.SubjectRecipient) r;
        assertEquals(Recipient.SubjectType.DEVICE, sr.type());
        assertEquals("SN123", sr.value());
    }

    @Test
    void ofUser_createsSubjectRecipientWithUser() {
        Recipient r = Recipient.ofUser("UID123");
        Recipient.SubjectRecipient sr = (Recipient.SubjectRecipient) r;
        assertEquals(Recipient.SubjectType.USER, sr.type());
        assertEquals("UID123", sr.value());
    }

    @Test
    void ofSerial_createsSubjectRecipientWithSerial() {
        Recipient r = Recipient.ofSerial("CERT-SN-001");
        Recipient.SubjectRecipient sr = (Recipient.SubjectRecipient) r;
        assertEquals(Recipient.SubjectType.SERIAL, sr.type());
        assertEquals("CERT-SN-001", sr.value());
    }

    @Test
    void certRecipient_nullCertDer_throwsNpe() {
        assertThrows(NullPointerException.class, () -> Recipient.ofCert(null));
    }

    @Test
    void publicKeyRecipient_nullSpki_throwsNpe() {
        assertThrows(NullPointerException.class, () -> Recipient.ofPublicKey(null));
    }

    @Test
    void subjectRecipient_nullType_throwsNpe() {
        assertThrows(NullPointerException.class, () -> new Recipient.SubjectRecipient(null, "val"));
    }

    @Test
    void subjectRecipient_nullValue_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> new Recipient.SubjectRecipient(Recipient.SubjectType.VIN, null));
    }

    @Test
    void envelopedData_encAlgHasTwoValues() {
        assertEquals(2, EnvelopedData.EncAlg.values().length);
        assertSame(EnvelopedData.EncAlg.ECIES_AES_256_GCM,
                EnvelopedData.EncAlg.valueOf("ECIES_AES_256_GCM"));
        assertSame(EnvelopedData.EncAlg.RSA_OAEP_AES_256_GCM,
                EnvelopedData.EncAlg.valueOf("RSA_OAEP_AES_256_GCM"));
    }

    @Test
    void envelopedData_nullCiphertext_throwsNpe() {
        assertThrows(NullPointerException.class, () ->
                new EnvelopedData(null, new byte[]{1}, EnvelopedData.EncAlg.ECIES_AES_256_GCM, new byte[]{2}));
    }

    @Test
    void envelopedData_nullAlg_throwsNpe() {
        assertThrows(NullPointerException.class, () ->
                new EnvelopedData(new byte[]{1}, new byte[]{2}, null, new byte[]{3}));
    }
}
