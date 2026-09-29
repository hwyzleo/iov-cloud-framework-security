package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * EnrollmentIdempotencyService 单元测试（FW-SEC-DSN-CR-008 §5.2/§6）
 */
class EnrollmentIdempotencyServiceTest {

    private final InMemoryCertificateEnrollmentResultStore store =
            new InMemoryCertificateEnrollmentResultStore(Duration.ofMinutes(30), 100);
    private final EnrollmentIdempotencyService service = new EnrollmentIdempotencyService(store);

    private byte[] csr(String marker) {
        return ("-----BEGIN CERTIFICATE REQUEST-----\n" + marker + "\n-----END CERTIFICATE REQUEST-----")
                .getBytes();
    }

    @Test
    void findExisting_shouldReturnEmpty_whenNoRecord() {
        assertEquals(Optional.empty(),
                service.findExisting("caller-1", "idem-1", csr("A"), "TBOX_IDENTITY"));
    }

    @Test
    void findExisting_shouldReturnRecord_whenSameParams() {
        byte[] csr = csr("A");
        store.createSubmitting("req-1", "caller-1", "idem-1", csr,
                EnrollmentRecord.sha256Hex(csr), "TBOX_IDENTITY");

        Optional<EnrollmentRecord> existing =
                service.findExisting("caller-1", "idem-1", csr, "TBOX_IDENTITY");

        assertTrue(existing.isPresent());
        assertEquals("req-1", existing.get().requestId());
    }

    @Test
    void findExisting_shouldThrowConflict_whenCsrDiffers() {
        store.createSubmitting("req-1", "caller-1", "idem-1", csr("A"),
                EnrollmentRecord.sha256Hex(csr("A")), "TBOX_IDENTITY");

        assertThrows(CertificateIdempotencyConflictException.class,
                () -> service.findExisting("caller-1", "idem-1", csr("B"), "TBOX_IDENTITY"));
    }

    @Test
    void findExisting_shouldThrowConflict_whenProfileDiffers() {
        byte[] csr = csr("A");
        store.createSubmitting("req-1", "caller-1", "idem-1", csr,
                EnrollmentRecord.sha256Hex(csr), "TBOX_IDENTITY");

        assertThrows(CertificateIdempotencyConflictException.class,
                () -> service.findExisting("caller-1", "idem-1", csr, "SERVICE_MTLS"));
    }

    @Test
    void findExisting_shouldReturnUnknownRecord_withoutReissue() {
        byte[] csr = csr("A");
        store.createSubmitting("req-1", "caller-1", "idem-1", csr,
                EnrollmentRecord.sha256Hex(csr), "TBOX_IDENTITY");
        store.markUnknown("req-1", "response lost");

        Optional<EnrollmentRecord> existing =
                service.findExisting("caller-1", "idem-1", csr, "TBOX_IDENTITY");

        assertTrue(existing.isPresent());
        assertTrue(EnrollmentIdempotencyService.isUnknownOutcome(existing.get()));
        assertEquals(EnrollmentState.UNKNOWN, existing.get().state());
    }

    @Test
    void findExisting_shouldScopeByCaller() {
        byte[] csr = csr("A");
        store.createSubmitting("req-1", "caller-1", "idem-1", csr,
                EnrollmentRecord.sha256Hex(csr), "TBOX_IDENTITY");

        // 不同 caller 相同 key：互不影响
        assertEquals(Optional.empty(),
                service.findExisting("caller-2", "idem-1", csr, "TBOX_IDENTITY"));
    }

    @Test
    void isUnknownOutcome_shouldDetectUnknown() {
        byte[] csr = csr("A");
        store.createSubmitting("req-1", "caller-1", "idem-1", csr,
                EnrollmentRecord.sha256Hex(csr), "TBOX_IDENTITY");
        store.markUnknown("req-1", "lost");
        assertTrue(EnrollmentIdempotencyService.isUnknownOutcome(
                store.findByRequestId("req-1").orElseThrow()));

        store.markTerminal("req-1", EnrollmentState.ISSUED, null);
        assertFalse(EnrollmentIdempotencyService.isUnknownOutcome(
                store.findByRequestId("req-1").orElseThrow()));
    }

    @Test
    void isRetryableTerminal_shouldAllowFailedAndRejected_only() {
        byte[] csr = csr("A");
        String sha = EnrollmentRecord.sha256Hex(csr);
        store.createSubmitting("req-1", "caller-1", "idem-1", csr, sha, "TBOX_IDENTITY");
        store.markTerminal("req-1", EnrollmentState.FAILED, "failed");
        assertTrue(EnrollmentIdempotencyService.isRetryableTerminal(
                store.findByRequestId("req-1").orElseThrow()));

        store.markTerminal("req-1", EnrollmentState.REJECTED, "rejected");
        assertTrue(EnrollmentIdempotencyService.isRetryableTerminal(
                store.findByRequestId("req-1").orElseThrow()));

        store.markTerminal("req-1", EnrollmentState.UNKNOWN, "unknown");
        assertFalse(EnrollmentIdempotencyService.isRetryableTerminal(
                store.findByRequestId("req-1").orElseThrow()), "UNKNOWN 禁止自动重签");

        store.markTerminal("req-1", EnrollmentState.ISSUED, null);
        assertFalse(EnrollmentIdempotencyService.isRetryableTerminal(
                store.findByRequestId("req-1").orElseThrow()), "ISSUED 禁止重签");

        store.markTerminal("req-1", EnrollmentState.PENDING, null);
        assertFalse(EnrollmentIdempotencyService.isRetryableTerminal(
                store.findByRequestId("req-1").orElseThrow()), "进行中禁止重签");
    }
}
