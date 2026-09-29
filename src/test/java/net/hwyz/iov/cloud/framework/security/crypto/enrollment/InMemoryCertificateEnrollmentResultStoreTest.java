package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * InMemoryCertificateEnrollmentResultStore 单元测试（FW-SEC-DSN-CR-008 §5.1）
 */
class InMemoryCertificateEnrollmentResultStoreTest {

    private final InMemoryCertificateEnrollmentResultStore store =
            new InMemoryCertificateEnrollmentResultStore(Duration.ofMinutes(30), 100);

    private EnrollmentRecord createSubmitting(String requestId, String idemKey) {
        return store.createSubmitting(requestId, "caller-1", idemKey,
                new byte[]{1, 2, 3}, EnrollmentRecord.sha256Hex(new byte[]{1, 2, 3}), "TBOX_IDENTITY");
    }

    @Test
    void createSubmitting_shouldPersistAndBeFindable() {
        EnrollmentRecord record = createSubmitting("req-1", "idem-1");

        assertEquals(EnrollmentState.SUBMITTING, record.state());
        assertEquals(record, store.findByRequestId("req-1").orElseThrow());
        assertEquals(record, store.findByIdempotency("caller-1", "idem-1").orElseThrow());
    }

    @Test
    void createSubmitting_shouldBeIdempotent_forSameRequestId() {
        createSubmitting("req-1", "idem-1");
        EnrollmentRecord second = createSubmitting("req-1", "idem-1");

        assertEquals("req-1", second.requestId());
        assertEquals(1, store.findByRequestId("req-1").map(r -> 1).orElse(0));
    }

    @Test
    void createSubmitting_shouldReturnExisting_forConcurrentSameIdemKey() {
        createSubmitting("req-1", "idem-same");
        EnrollmentRecord concurrent = createSubmitting("req-2", "idem-same");

        // 并发同 key：返回既有记录，不双写
        assertEquals("req-1", concurrent.requestId());
    }

    @Test
    void markIssued_shouldStoreCertificateMaterial() {
        createSubmitting("req-1", "idem-1");
        IssuedCertificate issued = new IssuedCertificate(
                new byte[]{10}, List.of(new byte[]{11}, new byte[]{12}), "serial-1",
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600), "fp-1");

        store.markIssued("req-1", issued);

        EnrollmentRecord record = store.findByRequestId("req-1").orElseThrow();
        assertEquals(EnrollmentState.ISSUED, record.state());
        assertEquals("serial-1", record.serialNumber());
        assertArrayEquals(new byte[]{10}, record.leafCertificate());
        assertEquals(2, record.certificateChain().size());
        assertEquals("fp-1", record.sha256Fingerprint());
        assertNotNull(record.notBefore());
    }

    @Test
    void markTerminal_shouldStoreRedactedError() {
        createSubmitting("req-1", "idem-1");
        store.markTerminal("req-1", EnrollmentState.REJECTED, "rejected by CA policy");

        EnrollmentRecord record = store.findByRequestId("req-1").orElseThrow();
        assertEquals(EnrollmentState.REJECTED, record.state());
        assertEquals("rejected by CA policy", record.errorSummary());
    }

    @Test
    void markUnknown_shouldSetUnknownState() {
        createSubmitting("req-1", "idem-1");
        store.markUnknown("req-1", "response lost");

        assertEquals(EnrollmentState.UNKNOWN,
                store.findByRequestId("req-1").orElseThrow().state());
    }

    @Test
    void findByRequestId_shouldExpireAfterTtl() throws InterruptedException {
        InMemoryCertificateEnrollmentResultStore shortTtl =
                new InMemoryCertificateEnrollmentResultStore(Duration.ofMillis(50), 100);
        shortTtl.createSubmitting("req-1", "caller-1", "idem-1", new byte[]{1},
                EnrollmentRecord.sha256Hex(new byte[]{1}), "P");

        Thread.sleep(120);
        assertEquals(Optional.empty(), shortTtl.findByRequestId("req-1"));
    }

    @Test
    void save_shouldUpsertLegacyRecord() {
        EnrollmentRecord record = new EnrollmentRecord(
                "req-pki", "caller-1", "idem-2", new byte[]{9},
                EnrollmentRecord.sha256Hex(new byte[]{9}), "SERVICE_MTLS",
                EnrollmentState.PENDING, null, null, null, null, null, null, null,
                Instant.now(), Instant.now());
        store.save(record);

        assertEquals(EnrollmentState.PENDING,
                store.findByRequestId("req-pki").orElseThrow().state());
        assertEquals("req-pki", store.findByIdempotency("caller-1", "idem-2")
                .orElseThrow().requestId());
    }

    @Test
    void createSubmitting_shouldSupersedeRetryableTerminal() {
        byte[] csr = new byte[]{1, 2, 3};
        createSubmitting("req-old", "idem-retry");
        store.markTerminal("req-old", EnrollmentState.FAILED, "failed");

        // 失败可重试：新 requestId 覆盖幂等索引，旧终态记录保留供审计
        EnrollmentRecord retry = store.createSubmitting("req-new", "caller-1", "idem-retry",
                csr, EnrollmentRecord.sha256Hex(csr), "TBOX_IDENTITY");

        assertEquals("req-new", retry.requestId());
        assertEquals("req-new", store.findByIdempotency("caller-1", "idem-retry")
                .orElseThrow().requestId());
        assertTrue(store.findByRequestId("req-old").isPresent(), "旧终态记录应保留");
    }

    @Test
    void createSubmitting_shouldNotSupersedeNonRetryable() {
        byte[] csr = new byte[]{1, 2, 3};
        createSubmitting("req-issued", "idem-issued");
        IssuedCertificate issued = new IssuedCertificate(
                new byte[]{10}, List.of(new byte[]{11}), "serial",
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600), "fp");
        store.markIssued("req-issued", issued);

        // ISSUED：返回既有记录，不覆盖
        EnrollmentRecord second = store.createSubmitting("req-new2", "caller-1", "idem-issued",
                csr, EnrollmentRecord.sha256Hex(csr), "TBOX_IDENTITY");
        assertEquals("req-issued", second.requestId());
        assertEquals("req-issued", store.findByIdempotency("caller-1", "idem-issued")
                .orElseThrow().requestId());
    }

    @Test
    void createSubmitting_shouldNotSupersedeUnknown() {
        byte[] csr = new byte[]{1, 2, 3};
        createSubmitting("req-unknown", "idem-unknown");
        store.markUnknown("req-unknown", "lost");

        // UNKNOWN：禁止自动重签，返回既有记录
        EnrollmentRecord second = store.createSubmitting("req-new3", "caller-1", "idem-unknown",
                csr, EnrollmentRecord.sha256Hex(csr), "TBOX_IDENTITY");
        assertEquals("req-unknown", second.requestId());
        assertEquals(EnrollmentState.UNKNOWN, second.state());
    }
}
