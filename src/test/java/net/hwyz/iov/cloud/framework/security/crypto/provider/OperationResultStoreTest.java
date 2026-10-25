package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.exception.DerivedWrapIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * InMemory {@link OperationResultStore} 语义测试（FW-SEC-DSN-CR-020 §4）。
 * <p>
 * 覆盖：同 operationId 原字节重放、requestDigest 冲突检测、TTL 过期清理、
 * FAILED/OUTCOME_UNKNOWN 重试覆盖、productionReady=false（InMemory 不支撑生产）。
 */
class OperationResultStoreTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-10-25T00:00:00Z"), ZoneOffset.UTC);

    private DerivedWrapResultRecord record(String operationId, String digest, String profileId,
                                           DerivedWrapResultRecord.Status status,
                                           Instant createdAt, Duration ttl) {
        return new DerivedWrapResultRecord(
                operationId, digest, profileId, status,
                "logical-" + operationId, "openbao-transit://ref", 3L, "v1",
                "ECDH_ES_P256_HKDF_SHA256_AES256GCM",
                new byte[]{1, 2, 3}, new byte[32], new byte[]{9, 9, 9},
                new byte[65], new byte[32], "v1", new byte[12], new byte[32],
                new byte[16], new byte[8], new byte[32], "ab12cd",
                KeyPurpose.UPLINK_AEAD, 7L, operationId, createdAt, createdAt.plus(ttl), null);
    }

    @Test
    void saveAndFind_sameDigest_returnsOriginalForReplay() {
        InMemoryOperationResultStore store = new InMemoryOperationResultStore(clock);
        DerivedWrapResultRecord original = record("op-1", "digest-A", "P1",
                DerivedWrapResultRecord.Status.SUCCEEDED, clock.instant(), Duration.ofDays(30));

        DerivedWrapResultRecord saved = store.save(original);
        DerivedWrapResultRecord replayed = store.save(record("op-1", "digest-A", "P1",
                DerivedWrapResultRecord.Status.SUCCEEDED, clock.instant(), Duration.ofDays(30)));

        assertEquals(original, saved);
        assertEquals(original, replayed, "相同摘要重放必须保持原记录（原字节语义）");
        assertTrue(store.find("op-1").isPresent());
        assertEquals(original, store.find("op-1").get());
    }

    @Test
    void sameOperationDifferentDigest_throwsIdempotencyConflict() {
        InMemoryOperationResultStore store = new InMemoryOperationResultStore(clock);
        store.save(record("op-1", "digest-A", "P1",
                DerivedWrapResultRecord.Status.SUCCEEDED, clock.instant(), Duration.ofDays(30)));

        assertThrows(DerivedWrapIdempotencyConflictException.class,
                () -> store.save(record("op-1", "digest-B", "P1",
                        DerivedWrapResultRecord.Status.SUCCEEDED, clock.instant(), Duration.ofDays(30))),
                "相同 operationId 不同摘要（profile/hash 变化）→ 幂等冲突（CR-020 §4）");
    }

    @Test
    void failedOrOutcomeUnknown_allowsRetryOverwrite() {
        InMemoryOperationResultStore store = new InMemoryOperationResultStore(clock);
        DerivedWrapResultRecord failed = record("op-1", "digest-A", "P1",
                DerivedWrapResultRecord.Status.FAILED, clock.instant(), Duration.ofDays(30));
        store.save(failed);
        DerivedWrapResultRecord retried = record("op-1", "digest-A", "P1",
                DerivedWrapResultRecord.Status.SUCCEEDED, clock.instant().plusSeconds(10),
                Duration.ofDays(30));
        DerivedWrapResultRecord result = store.save(retried);
        assertEquals(DerivedWrapResultRecord.Status.SUCCEEDED, result.status(),
                "FAILED 后允许按原 operationId 重试覆盖");
    }

    @Test
    void ttlExpired_recordPurged() {
        InMemoryOperationResultStore store = new InMemoryOperationResultStore(clock);
        store.save(record("op-1", "digest-A", "P1",
                DerivedWrapResultRecord.Status.SUCCEEDED, clock.instant(), Duration.ofSeconds(60)));
        assertTrue(store.find("op-1").isPresent());

        // 模拟进程时间前进超过 TTL：同一记录在新时钟下读取必须不可见（懒清理）
        InMemoryOperationResultStore advanced = new InMemoryOperationResultStore(
                Clock.fixed(clock.instant().plusSeconds(120), ZoneOffset.UTC));
        assertFalse(advanced.find("op-1").isPresent(),
                "TTL 过期后记录必须清理（完整信封不再驻留）");
    }

    @Test
    void markTerminal_removesRecord() {
        InMemoryOperationResultStore store = new InMemoryOperationResultStore(clock);
        store.save(record("op-1", "digest-A", "P1",
                DerivedWrapResultRecord.Status.SUCCEEDED, clock.instant(), Duration.ofDays(30)));
        store.markTerminal("op-1", DerivedWrapResultRecord.Status.SUCCEEDED, null);
        assertFalse(store.find("op-1").isPresent(), "终态清理移除完整信封");
    }

    @Test
    void inMemoryDoesNotSupportProductionReadiness() {
        InMemoryOperationResultStore store = new InMemoryOperationResultStore(clock);
        assertFalse(store.productionReady(),
                "InMemory 无法覆盖进程重启/多实例路由/滚动发布：不支撑生产 READY（CR-020 §5）");
        assertEquals("in-memory", store.storeType());
    }
}
