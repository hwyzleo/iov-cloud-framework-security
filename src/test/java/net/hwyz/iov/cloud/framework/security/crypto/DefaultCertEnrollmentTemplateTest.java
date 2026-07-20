package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateApplicationRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateNotReadyException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.model.SubjectRef;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * DefaultCertEnrollmentTemplate 单元测试
 */
class DefaultCertEnrollmentTemplateTest {

    @Mock
    private PkiClient pkiClient;

    @Mock
    private CryptoMetrics cryptoMetrics;

    private DefaultCertEnrollmentTemplate template;

    private CertificateProfile allowedProfile;

    private CertificateProfile disallowedProfile;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        allowedProfile = new CertificateProfile(
                "SERVICE_MTLS",
                "pki-service-mtls",
                CertificateProfile.SubjectType.SERVICE,
                "RSA",
                "服务 mTLS 证书"
        );

        disallowedProfile = new CertificateProfile(
                "UNKNOWN_PROFILE",
                "pki-unknown",
                CertificateProfile.SubjectType.SERVICE,
                "RSA",
                "未知证书"
        );

        template = new DefaultCertEnrollmentTemplate(
                pkiClient,
                cryptoMetrics,
                List.of(allowedProfile)
        );
    }

    @Test
    void apply_shouldSucceed_withValidRequest() {
        // Given
        byte[] csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBPjCB...\n-----END CERTIFICATE REQUEST-----".getBytes();
        SubjectRef subject = new SubjectRef(SubjectRef.SubjectType.CN, "test-service");
        CertApplyRequest request = new CertApplyRequest(
                allowedProfile, csr, subject, "idempotency-key-1", Map.of()
        );

        PkiClient.ApplyResponse pkiResponse = new PkiClient.ApplyResponse(
                "request-123", "PENDING", "Submitted"
        );
        when(pkiClient.submit(any())).thenReturn(pkiResponse);

        // When
        CertApplyResult result = template.apply(request);

        // Then
        assertNotNull(result);
        assertEquals("request-123", result.requestId());
        assertEquals(EnrollmentState.PENDING, result.state());
        verify(pkiClient).submit(any());
        verify(cryptoMetrics).recordCertificateEnrollment(anyLong());
    }

    @Test
    void apply_shouldThrowException_withDisallowedProfile() {
        // Given
        byte[] csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBPjCB...\n-----END CERTIFICATE REQUEST-----".getBytes();
        SubjectRef subject = new SubjectRef(SubjectRef.SubjectType.CN, "test-service");
        CertApplyRequest request = new CertApplyRequest(
                disallowedProfile, csr, subject, "idempotency-key-2", Map.of()
        );

        // When & Then
        assertThrows(CertificateProfileNotAllowedException.class, () -> template.apply(request));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void apply_shouldThrowException_withEmptyCsr() {
        // Given
        byte[] csr = new byte[0];
        SubjectRef subject = new SubjectRef(SubjectRef.SubjectType.CN, "test-service");
        CertApplyRequest request = new CertApplyRequest(
                allowedProfile, csr, subject, "idempotency-key-3", Map.of()
        );

        // When & Then
        assertThrows(InvalidCertificateRequestException.class, () -> template.apply(request));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void apply_shouldReturnExistingRequestId_forDuplicateIdempotencyKey() {
        // Given
        byte[] csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBPjCB...\n-----END CERTIFICATE REQUEST-----".getBytes();
        SubjectRef subject = new SubjectRef(SubjectRef.SubjectType.CN, "test-service");
        CertApplyRequest request1 = new CertApplyRequest(
                allowedProfile, csr, subject, "idempotency-key-4", Map.of()
        );
        CertApplyRequest request2 = new CertApplyRequest(
                allowedProfile, csr, subject, "idempotency-key-4", Map.of()
        );

        PkiClient.ApplyResponse pkiResponse = new PkiClient.ApplyResponse(
                "request-456", "PENDING", "Submitted"
        );
        when(pkiClient.submit(any())).thenReturn(pkiResponse);

        PkiClient.StatusResponse statusResponse = new PkiClient.StatusResponse(
                "request-456", "PENDING", "Processing"
        );
        when(pkiClient.getStatus("request-456")).thenReturn(statusResponse);

        // When
        template.apply(request1);
        CertApplyResult result2 = template.apply(request2);

        // Then
        assertEquals("request-456", result2.requestId());
        verify(pkiClient, times(1)).submit(any());
    }

    @Test
    void getStatus_shouldReturnCurrentState() {
        // Given
        PkiClient.StatusResponse statusResponse = new PkiClient.StatusResponse(
                "request-789", "ISSUED", "Certificate issued"
        );
        when(pkiClient.getStatus("request-789")).thenReturn(statusResponse);

        // When
        CertApplyResult result = template.getStatus("request-789");

        // Then
        assertNotNull(result);
        assertEquals("request-789", result.requestId());
        assertEquals(EnrollmentState.ISSUED, result.state());
        verify(cryptoMetrics).recordCertificateEnrollmentQuery(anyLong());
    }

    @Test
    void getCertificate_shouldReturnIssuedCertificate() {
        // Given
        PkiClient.StatusResponse statusResponse = new PkiClient.StatusResponse(
                "request-101", "ISSUED", "Certificate issued"
        );
        when(pkiClient.getStatus("request-101")).thenReturn(statusResponse);

        byte[] leafCert = new byte[]{0x30, 0x01, 0x02}; // Mock DER
        byte[] certChain = new byte[]{0x30, 0x01, 0x02}; // Mock DER
        PkiClient.CertificateResponse certResponse = new PkiClient.CertificateResponse(
                "request-101",
                leafCert,
                certChain,
                "1234567890",
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z"
        );
        when(pkiClient.getCertificate("request-101")).thenReturn(certResponse);

        // When
        IssuedCertificate result = template.getCertificate("request-101");

        // Then
        assertNotNull(result);
        assertArrayEquals(leafCert, result.leafCertificate());
        assertEquals("1234567890", result.serialNumber());
        assertNotNull(result.sha256Fingerprint());
    }

    @Test
    void getCertificate_shouldThrowException_whenNotIssued() {
        // Given
        PkiClient.StatusResponse statusResponse = new PkiClient.StatusResponse(
                "request-202", "PENDING", "Processing"
        );
        when(pkiClient.getStatus("request-202")).thenReturn(statusResponse);

        // When & Then
        assertThrows(CertificateNotReadyException.class, () -> template.getCertificate("request-202"));
    }
}
