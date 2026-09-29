package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 进程内（有界）证书注册结果存储（FW-SEC-DSN-CR-008 §5.1）
 * <p>
 * 仅用于开发/测试：数据不共享、重启即失。生产 profile 下搭配 step-ca 装配时由装配层拒绝启动。
 * 有界容量 + TTL，容量/条目达到上限时按最旧淘汰。
 */
public class InMemoryCertificateEnrollmentResultStore implements CertificateEnrollmentResultStore {

    private final Duration ttl;
    private final int maxEntries;
    private final Map<String, EnrollmentRecord> byRequestId = new ConcurrentHashMap<>();
    private final Map<String, String> byIdempotency = new ConcurrentHashMap<>();

    public InMemoryCertificateEnrollmentResultStore(Duration ttl, int maxEntries) {
        this.ttl = ttl == null ? Duration.ofDays(30) : ttl;
        this.maxEntries = maxEntries <= 0 ? 1000 : maxEntries;
    }

    @Override
    public Optional<EnrollmentRecord> findByRequestId(String requestId) {
        EnrollmentRecord record = byRequestId.get(requestId);
        if (record == null || expired(record)) {
            return Optional.empty();
        }
        return Optional.of(record);
    }

    @Override
    public Optional<EnrollmentRecord> findByIdempotency(String caller, String idempotencyKey) {
        String requestId = byIdempotency.get(indexKey(caller, idempotencyKey));
        if (requestId == null) {
            return Optional.empty();
        }
        return findByRequestId(requestId);
    }

    @Override
    public synchronized EnrollmentRecord createSubmitting(String requestId, String caller, String idempotencyKey,
                                                         byte[] csr, String csrSha256, String profileName) {
        String idemKey = indexKey(caller, idempotencyKey);
        EnrollmentRecord existing = byRequestId.get(requestId);
        if (existing != null) {
            return existing;
        }
        String existingId = byIdempotency.get(idemKey);
        if (existingId != null && !existingId.equals(requestId)) {
            EnrollmentRecord existingRecord = byRequestId.get(existingId);
            // 可重试终态（FAILED/REJECTED）：覆盖索引允许重签；否则返回既有记录
            if (existingRecord != null
                    && !EnrollmentIdempotencyService.isRetryableTerminal(existingRecord)) {
                return existingRecord;
            }
        }
        evictIfNeeded();
        Instant now = Instant.now();
        EnrollmentRecord record = new EnrollmentRecord(requestId, caller, idempotencyKey, csr, csrSha256,
                profileName, EnrollmentState.SUBMITTING, null, null, null, null, null, null, null, now, now);
        byRequestId.put(requestId, record);
        // 重试场景需覆盖旧索引（put 而非 putIfAbsent）
        byIdempotency.put(idemKey, requestId);
        return record;
    }

    @Override
    public EnrollmentRecord save(EnrollmentRecord record) {
        byRequestId.put(record.requestId(), record);
        byIdempotency.put(indexKey(record.caller(), record.idempotencyKey()), record.requestId());
        return record;
    }

    @Override
    public void markIssued(String requestId, IssuedCertificate certificate) {
        byRequestId.computeIfPresent(requestId, (id, record) -> new EnrollmentRecord(
                record.requestId(), record.caller(), record.idempotencyKey(), record.csr(),
                record.csrSha256(), record.profileName(), EnrollmentState.ISSUED,
                certificate.serialNumber(), certificate.leafCertificate(), certificate.certificateChain(),
                certificate.notBefore().toString(), certificate.notAfter().toString(),
                certificate.sha256Fingerprint(), null, record.createdAt(), Instant.now()));
    }

    @Override
    public void markTerminal(String requestId, EnrollmentState state, String errorSummary) {
        byRequestId.computeIfPresent(requestId,
                (id, record) -> record.withState(state)
                        .withErrorSummary(errorSummary));
    }

    @Override
    public void markUnknown(String requestId, String errorSummary) {
        byRequestId.computeIfPresent(requestId,
                (id, record) -> record.withState(EnrollmentState.UNKNOWN)
                        .withErrorSummary(errorSummary));
    }

    private boolean expired(EnrollmentRecord record) {
        return record.updatedAt().plus(ttl).isBefore(Instant.now());
    }

    private void evictIfNeeded() {
        while (byRequestId.size() >= maxEntries) {
            String oldest = null;
            Instant oldestUpdated = Instant.MAX;
            for (EnrollmentRecord record : byRequestId.values()) {
                if (record.updatedAt().isBefore(oldestUpdated)) {
                    oldestUpdated = record.updatedAt();
                    oldest = record.requestId();
                }
            }
            if (oldest == null) {
                break;
            }
            byRequestId.remove(oldest);
        }
    }

    private static String indexKey(String caller, String idempotencyKey) {
        return caller + ":" + idempotencyKey;
    }
}
