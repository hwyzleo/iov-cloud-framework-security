package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceMismatchException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 统一证书证据校验器单元测试（FW-SEC-DSN-CR-012 §6/§10）。
 */
class CertificateEvidenceValidatorTest {

    private CryptoProperties properties;
    private PkiClient pkiClient;
    private TestPkiMaterial.Pki pki;
    private CertificateEvidenceValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        pki = TestPkiMaterial.generate();
        properties = new CryptoProperties();
        properties.getPki().getCertificateResolution().setEnabled(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(
                TestPkiMaterial.pem("CERTIFICATE", pki.intermediateCert().getEncoded()));
        pkiClient = mock(PkiClient.class);
        validator = new CertificateEvidenceValidator(new TestObjectProvider<>(pkiClient), properties);
    }

    private byte[] leafDer() throws Exception {
        return pki.leafCert().getEncoded();
    }

    private List<byte[]> chain() throws Exception {
        return List.of(pki.intermediateCert().getEncoded(), pki.rootCert().getEncoded());
    }

    private CertificateResolvePolicy trustedChainPolicy() {
        return CertificateResolvePolicy.businessKeyWrap(true, true, false);
    }

    @Test
    void validate_inlineDerWithTrustedChain_success() throws Exception {
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                leafDer(), chain(), EvidenceSource.INLINE_DER);
        String serial = PkiClient.canonicalSerial(pki.leafCert().getSerialNumber().toString(16));
        DeviceCertificateRef ref = DeviceCertificateRef.ofSerial(serial);

        CertificateEvidence result = validator.validate(evidence, ref, trustedChainPolicy());

        assertNotNull(result);
        assertEquals(serial, result.serial());
        assertTrue(result.hasSpki());
        assertTrue(result.hasLeafDer());
    }

    @Test
    void validate_declaredFingerprintMismatch_throws() throws Exception {
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                leafDer(), chain(), EvidenceSource.INLINE_DER);
        DeviceCertificateRef ref = DeviceCertificateRef.ofSerial("3").withFingerprint("deadbeef");

        assertThrows(CertificateEvidenceMismatchException.class,
                () -> validator.validate(evidence, ref, trustedChainPolicy()));
    }

    @Test
    void validate_declaredSerialMismatch_throws() throws Exception {
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                leafDer(), chain(), EvidenceSource.INLINE_DER);
        DeviceCertificateRef ref = DeviceCertificateRef.ofSerial("9999");

        assertThrows(CertificateEvidenceMismatchException.class,
                () -> validator.validate(evidence, ref, trustedChainPolicy()));
    }

    @Test
    void validate_leafSelfSignedNotAnchored_chainUntrusted() throws Exception {
        KeyPair keyPair = TestPkiMaterial.generateKeyPair();
        X509Certificate rogue = TestPkiMaterial.issueSelfSigned(
                new org.bouncycastle.asn1.x500.X500Name("CN=rogue"), keyPair,
                java.math.BigInteger.valueOf(77));
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                rogue.getEncoded(), List.of(), EvidenceSource.INLINE_DER);

        assertThrows(CertificateMaterialUnavailableException.class,
                () -> validator.validate(evidence, null, trustedChainPolicy()));
    }

    @Test
    void validate_missingTrustAnchors_failClosed() throws Exception {
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(null);
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                leafDer(), chain(), EvidenceSource.INLINE_DER);

        CertificateMaterialUnavailableException ex = assertThrows(CertificateMaterialUnavailableException.class,
                () -> validator.validate(evidence, null, trustedChainPolicy()));
        assertTrue(ex.getMessage().contains("trust-anchors-pem"));
    }

    @Test
    void validate_expiredCertificate_failClosed() throws Exception {
        KeyPair keyPair = TestPkiMaterial.generateKeyPair();
        X509Certificate expired = TestPkiMaterial.issueEndEntitySelfSignedWithValidity(
                new org.bouncycastle.asn1.x500.X500Name("CN=expired"), keyPair,
                java.math.BigInteger.valueOf(88),
                Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600));
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                expired.getEncoded(), List.of(), EvidenceSource.INLINE_DER);

        CertificateMaterialUnavailableException ex = assertThrows(CertificateMaterialUnavailableException.class,
                () -> validator.validate(evidence, null,
                        CertificateResolvePolicy.businessKeyWrap(true, false, false)));
        assertTrue(ex.getMessage().contains("expired") || ex.getMessage().contains("not yet valid"));
    }

    @Test
    void validate_requiredEkuMissing_failClosed() throws Exception {
        // TestPkiMaterial.generate(false, null) 的叶子证书无 EKU
        TestPkiMaterial.Pki noEku = TestPkiMaterial.generate(false, null);
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                noEku.leafCert().getEncoded(), List.of(), EvidenceSource.INLINE_DER);
        CertificateResolvePolicy policy = new CertificateResolvePolicy(
                CertificateResolvePolicy.Scenario.BUSINESS_KEY_WRAP, true, false, false, false,
                java.util.Set.of("RSA", "EC"), java.util.Set.of("clientAuth"));

        CertificateMaterialUnavailableException ex = assertThrows(CertificateMaterialUnavailableException.class,
                () -> validator.validate(evidence, null, policy));
        assertTrue(ex.getMessage().contains("EKU"));
    }

    @Test
    void validate_spkiOnly_allowedForCertEncryption() throws Exception {
        byte[] spki = pki.leafKeyPair().getPublic().getEncoded();
        CertificateEvidence evidence = CertificateEvidenceValidator.fromSpki(
                spki, null, EvidenceSource.INLINE_SPKI);

        CertificateEvidence result = validator.validate(evidence, null,
                CertificateResolvePolicy.certEncryption());

        assertNotNull(result);
        assertFalse(result.hasLeafDer());
        assertTrue(result.hasSpki());
    }

    @Test
    void validate_spkiOnly_rejectedForBusinessKeyWrap() throws Exception {
        byte[] spki = pki.leafKeyPair().getPublic().getEncoded();
        CertificateEvidence evidence = CertificateEvidenceValidator.fromSpki(
                spki, null, EvidenceSource.INLINE_SPKI);

        assertThrows(CertificateMaterialUnavailableException.class,
                () -> validator.validate(evidence, null,
                        CertificateResolvePolicy.businessKeyWrap(true, false, false)));
    }

    @Test
    void validate_revokedStatus_failClosed() throws Exception {
        when(pkiClient.checkCertificateStatus(any())).thenReturn(status(
                PkiClient.RevocationState.REVOKED, pki.leafCert()));
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                leafDer(), List.of(), EvidenceSource.INLINE_DER);

        CertificateMaterialUnavailableException ex = assertThrows(CertificateMaterialUnavailableException.class,
                () -> validator.validate(evidence, null,
                        CertificateResolvePolicy.businessKeyWrap(true, false, true)));
        assertTrue(ex.getMessage().contains("REVOKED"));
    }

    @Test
    void validate_unknownStatus_failClosed() throws Exception {
        when(pkiClient.checkCertificateStatus(any())).thenReturn(status(
                PkiClient.RevocationState.UNKNOWN, pki.leafCert()));
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                leafDer(), List.of(), EvidenceSource.INLINE_DER);

        assertThrows(CertificateMaterialUnavailableException.class,
                () -> validator.validate(evidence, null,
                        CertificateResolvePolicy.businessKeyWrap(true, false, true)));
    }

    @Test
    void validate_goodStatus_success() throws Exception {
        when(pkiClient.checkCertificateStatus(any())).thenReturn(status(
                PkiClient.RevocationState.GOOD, pki.leafCert()));
        CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                leafDer(), List.of(), EvidenceSource.INLINE_DER);

        assertNotNull(validator.validate(evidence, null,
                CertificateResolvePolicy.businessKeyWrap(true, false, true)));
    }

    private static PkiClient.CertificateStatusResult status(PkiClient.RevocationState state,
                                                            X509Certificate leaf) {
        return new PkiClient.CertificateStatusResult(state, "TBOX-test",
                leaf.getNotBefore().toInstant(), leaf.getNotAfter().toInstant(),
                Instant.now(), null, PkiClient.RevocationSource.OCSP, Instant.now());
    }
}
