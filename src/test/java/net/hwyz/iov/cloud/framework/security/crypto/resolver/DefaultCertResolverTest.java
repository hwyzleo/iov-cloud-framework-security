package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.CertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.EnrollmentRecord;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateReferenceAmbiguousException;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * framework 默认证书解析编排单元测试（FW-SEC-DSN-CR-012 §6/§10）。
 */
class DefaultCertResolverTest {

    private CryptoProperties properties;
    private CertificateEnrollmentResultStore resultStore;
    private CertEnrollmentTemplate enrollmentTemplate;
    private PkiClient pkiClient;
    private TestPkiMaterial.Pki pki;

    @BeforeEach
    void setUp() throws Exception {
        properties = new CryptoProperties();
        properties.getPki().getCertificateResolution().setEnabled(true);
        properties.getPki().getCertificateResolution().setProviderQueryEnabled(true);
        properties.getPki().getCertificateResolution().setDomainDirectoryEnabled(true);
        resultStore = mock(CertificateEnrollmentResultStore.class);
        enrollmentTemplate = mock(CertEnrollmentTemplate.class);
        pkiClient = mock(PkiClient.class);
        pki = TestPkiMaterial.generate();
    }

    private DefaultCertResolver resolver() {
        return resolver(new TestObjectProvider<>());
    }

    private DefaultCertResolver resolver(TestObjectProvider<CertificateReferenceDirectory> directories) {
        return new DefaultCertResolver(
                new TestObjectProvider<>(resultStore),
                new TestObjectProvider<>(enrollmentTemplate),
                new TestObjectProvider<>(pkiClient),
                directories,
                properties);
    }

    private EnrollmentRecord record(EnrollmentState state) throws Exception {
        return new EnrollmentRecord("req-1", "caller", "idem-1", new byte[]{1}, "csr-hash", "TBOX_TSP_CLIENT",
                state, pki.leafCert().getSerialNumber().toString(16), pki.leafCert().getEncoded(),
                List.of(pki.intermediateCert().getEncoded(), pki.rootCert().getEncoded()),
                null, null, null, null, Instant.now(), Instant.now());
    }

    private CertificateResolvePolicy policy() {
        return CertificateResolvePolicy.businessKeyWrap(true, true, true);
    }

    @Test
    void resolve_inlineDer_returnsInlineSource() throws Exception {
        CertificateEvidence evidence = resolver().resolve(
                DeviceCertificateRef.ofCertificate(pki.leafCert().getEncoded()), policy());

        assertEquals(EvidenceSource.INLINE_DER, evidence.source());
        assertTrue(evidence.hasLeafDer());
    }

    @Test
    void resolve_inlineSpki_certEncryptionPolicy_returnsInlineSpki() throws Exception {
        CertificateEvidence evidence = resolver().resolve(
                DeviceCertificateRef.ofSpki(pki.leafKeyPair().getPublic().getEncoded()),
                CertificateResolvePolicy.certEncryption());

        assertEquals(EvidenceSource.INLINE_SPKI, evidence.source());
        assertTrue(evidence.hasSpki());
    }

    @Test
    void resolve_inlineSpki_businessKeyWrapPolicy_failClosed() throws Exception {
        assertThrows(CertificateMaterialUnavailableException.class,
                () -> resolver().resolve(
                        DeviceCertificateRef.ofSpki(pki.leafKeyPair().getPublic().getEncoded()), policy()));
    }

    @Test
    void resolve_requestIdFromResultStore_returnsEnrollmentSource() throws Exception {
        when(resultStore.findByRequestId("req-1")).thenReturn(Optional.of(record(EnrollmentState.ISSUED)));

        CertificateEvidence evidence = resolver().resolve(
                DeviceCertificateRef.ofRequestId("req-1"), policy());

        assertEquals(EvidenceSource.ENROLLMENT_STORE, evidence.source());
        assertTrue(evidence.hasLeafDer());
    }

    @Test
    void resolve_requestIdNotIssued_failClosed() throws Exception {
        when(resultStore.findByRequestId("req-1")).thenReturn(Optional.of(record(EnrollmentState.PENDING)));

        assertThrows(CertificateMaterialUnavailableException.class,
                () -> resolver().resolve(DeviceCertificateRef.ofRequestId("req-1"), policy()));
    }

    @Test
    void resolve_requestIdViaEnrollmentTemplate_returnsEnrollmentSource() throws Exception {
        when(resultStore.findByRequestId("req-1")).thenReturn(Optional.empty());
        when(enrollmentTemplate.getCertificate("req-1")).thenReturn(new IssuedCertificate(
                pki.leafCert().getEncoded(),
                List.of(pki.intermediateCert().getEncoded(), pki.rootCert().getEncoded()),
                pki.leafCert().getSerialNumber().toString(16),
                pki.leafCert().getNotBefore().toInstant(), pki.leafCert().getNotAfter().toInstant(),
                "fingerprint"));

        CertificateEvidence evidence = resolver().resolve(
                DeviceCertificateRef.ofRequestId("req-1"), policy());

        assertEquals(EvidenceSource.ENROLLMENT_STORE, evidence.source());
    }

    @Test
    void resolve_providerSerialQuery_legacyProvider_returnsProviderSource() throws Exception {
        when(pkiClient.queryCertificate("3")).thenReturn(new PkiClient.CertificateResponse(
                "req-1", pki.leafCert().getEncoded(), null,
                pki.leafCert().getSerialNumber().toString(16), null, null));

        CertificateEvidence evidence = resolver().resolve(DeviceCertificateRef.ofSerial("3"), policy());

        assertEquals(EvidenceSource.PROVIDER_QUERY, evidence.source());
    }

    @Test
    void resolve_providerSerialQuery_stepCa_skipsToDomainDirectory() throws Exception {
        properties.getPki().setProvider("step-ca");
        CertificateReferenceDirectory directory =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-1"));
        when(resultStore.findByRequestId("req-1")).thenReturn(Optional.of(record(EnrollmentState.ISSUED)));

        CertificateEvidence evidence = resolver(new TestObjectProvider<>(directory))
                .resolve(DeviceCertificateRef.ofSerial("3"), policy());

        assertEquals(EvidenceSource.DOMAIN_DIRECTORY, evidence.source());
    }

    @Test
    void resolve_domainDirectorySerialToRequestId_returnsDomainSource() throws Exception {
        CertificateReferenceDirectory directory =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-1"));
        when(resultStore.findByRequestId("req-1")).thenReturn(Optional.of(record(EnrollmentState.ISSUED)));

        CertificateEvidence evidence = resolver(new TestObjectProvider<>(directory))
                .resolve(DeviceCertificateRef.ofSerial("3"), policy());

        assertEquals(EvidenceSource.DOMAIN_DIRECTORY, evidence.source());
        assertTrue(evidence.hasLeafDer());
    }

    @Test
    void resolve_domainDirectorySubjectToRequestId_returnsDomainSource() throws Exception {
        CertificateReferenceDirectory directory =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-1"));
        when(resultStore.findByRequestId("req-1")).thenReturn(Optional.of(record(EnrollmentState.ISSUED)));

        CertificateEvidence evidence = resolver(new TestObjectProvider<>(directory))
                .resolve(DeviceCertificateRef.ofSubject(CertificateSubjectRef.ofDevice("SN-1")), policy());

        assertEquals(EvidenceSource.DOMAIN_DIRECTORY, evidence.source());
    }

    @Test
    void resolve_multipleDirectoriesDifferentLocators_ambiguous() {
        CertificateReferenceDirectory first =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-1"));
        CertificateReferenceDirectory second =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-2"));

        assertThrows(CertificateReferenceAmbiguousException.class,
                () -> resolver(new TestObjectProvider<>(first, second))
                        .resolve(DeviceCertificateRef.ofSerial("3"), policy()));
    }

    @Test
    void resolve_multipleDirectoriesSameLocator_success() throws Exception {
        CertificateReferenceDirectory first =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-1"));
        CertificateReferenceDirectory second =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-1"));
        when(resultStore.findByRequestId("req-1")).thenReturn(Optional.of(record(EnrollmentState.ISSUED)));

        CertificateEvidence evidence = resolver(new TestObjectProvider<>(first, second))
                .resolve(DeviceCertificateRef.ofSerial("3"), policy());

        assertEquals(EvidenceSource.DOMAIN_DIRECTORY, evidence.source());
    }

    @Test
    void resolve_noSource_failClosed() {
        assertThrows(CertificateMaterialUnavailableException.class,
                () -> resolver().resolve(DeviceCertificateRef.ofSerial("3"), policy()));
    }

    @Test
    void resolveBySerial_legacyMethod_delegatesToResolve() throws Exception {
        when(pkiClient.queryCertificate("3")).thenReturn(new PkiClient.CertificateResponse(
                "req-1", pki.leafCert().getEncoded(), null,
                pki.leafCert().getSerialNumber().toString(16), null, null));

        byte[] der = resolver().resolveBySerial("3");

        assertArrayEquals(pki.leafCert().getEncoded(), der);
    }

    @Test
    void resolve_directoryReturnsProviderSerial_usesProviderQuery() throws Exception {
        CertificateReferenceDirectory directory =
                ref -> Optional.of(new CertificateLocator.ProviderSerial("3"));
        when(pkiClient.queryCertificate(eq("3"))).thenReturn(new PkiClient.CertificateResponse(
                "req-1", pki.leafCert().getEncoded(), null,
                pki.leafCert().getSerialNumber().toString(16), null, null));

        CertificateEvidence evidence = resolver(new TestObjectProvider<>(directory))
                .resolve(DeviceCertificateRef.ofRequestId("req-1"), policy());

        assertEquals(EvidenceSource.DOMAIN_DIRECTORY, evidence.source());
        verifyProviderQuery();
    }

    private void verifyProviderQuery() {
        org.mockito.Mockito.verify(pkiClient).queryCertificate("3");
    }
}
