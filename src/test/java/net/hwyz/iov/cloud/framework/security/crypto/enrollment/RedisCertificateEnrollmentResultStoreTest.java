package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RedisCertificateEnrollmentResultStore 测试（FW-SEC-DSN-CR-008 §5.1）
 * <p>
 * 生产实现走 Redis，必须覆盖：幂等索引、终态重试覆盖、UNKNOWN/ISSUED 不覆盖、
 * 并发重试不双签（Lua 原子槽位）、TTL。需要 Docker；无 Docker 时自动跳过。
 */
@Tag("contract")
@Testcontainers(disabledWithoutDocker = true)
class RedisCertificateEnrollmentResultStoreTest {

    @Container
    static final GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine")
            .withExposedPorts(6379);

    private static StringRedisTemplate redisTemplate;
    private static RedisCertificateEnrollmentResultStore store;

    private static final byte[] CSR = {1, 2, 3};
    private static final String CSR_SHA = EnrollmentRecord.sha256Hex(CSR);

    @BeforeAll
    static void setUp() {
        LettuceConnectionFactory factory =
                new LettuceConnectionFactory(redis.getHost(), redis.getMappedPort(6379));
        factory.afterPropertiesSet();
        redisTemplate = new StringRedisTemplate(factory);
        redisTemplate.afterPropertiesSet();
        store = new RedisCertificateEnrollmentResultStore(redisTemplate, Duration.ofMinutes(5));
    }

    @AfterAll
    static void tearDown() {
        if (redisTemplate != null && redisTemplate.getConnectionFactory() instanceof LettuceConnectionFactory factory) {
            factory.destroy();
        }
    }

    private void flush() {
        redisTemplate.getConnectionFactory().getConnection().serverCommands().flushDb();
    }

    @Test
    void createSubmitting_shouldPersistAndBeFindable() {
        flush();
        EnrollmentRecord record = store.createSubmitting("req-1", "caller-1", "idem-1", CSR, CSR_SHA, "TBOX_IDENTITY");

        assertEquals(EnrollmentState.SUBMITTING, record.state());
        assertEquals(record.requestId(),
                store.findByIdempotency("caller-1", "idem-1").orElseThrow().requestId());
        assertEquals(EnrollmentState.SUBMITTING,
                store.findByRequestId("req-1").orElseThrow().state());
    }

    @Test
    void markIssued_shouldRoundTripCertificateMaterial() {
        flush();
        store.createSubmitting("req-2", "caller-1", "idem-2", CSR, CSR_SHA, "TBOX_IDENTITY");
        IssuedCertificate issued = new IssuedCertificate(
                new byte[]{10}, List.of(new byte[]{11}, new byte[]{12}), "serial-2",
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600), "fp-2");
        store.markIssued("req-2", issued);

        EnrollmentRecord record = store.findByRequestId("req-2").orElseThrow();
        assertEquals(EnrollmentState.ISSUED, record.state());
        assertEquals("serial-2", record.serialNumber());
        assertArrayEquals(new byte[]{10}, record.leafCertificate());
        assertEquals(2, record.certificateChain().size());
    }

    @Test
    void createSubmitting_shouldSupersedeRetryableTerminal() {
        flush();
        store.createSubmitting("req-old", "caller-1", "idem-r", CSR, CSR_SHA, "TBOX_IDENTITY");
        store.markTerminal("req-old", EnrollmentState.FAILED, "failed");

        EnrollmentRecord retry = store.createSubmitting("req-new", "caller-1", "idem-r", CSR, CSR_SHA, "TBOX_IDENTITY");

        assertEquals("req-new", retry.requestId());
        assertEquals("req-new",
                store.findByIdempotency("caller-1", "idem-r").orElseThrow().requestId());
        assertTrue(store.findByRequestId("req-old").isPresent(), "旧 FAILED 记录应保留");
    }

    @Test
    void createSubmitting_shouldNotSupersedeUnknownOrIssued() {
        flush();
        // UNKNOWN：禁止自动重签
        store.createSubmitting("req-u", "caller-1", "idem-u", CSR, CSR_SHA, "TBOX_IDENTITY");
        store.markUnknown("req-u", "lost");
        EnrollmentRecord u = store.createSubmitting("req-u2", "caller-1", "idem-u", CSR, CSR_SHA, "TBOX_IDENTITY");
        assertEquals("req-u", u.requestId());
        assertEquals(EnrollmentState.UNKNOWN, u.state());

        // ISSUED：禁止重签
        store.createSubmitting("req-i", "caller-1", "idem-i", CSR, CSR_SHA, "TBOX_IDENTITY");
        store.markIssued("req-i", new IssuedCertificate(
                new byte[]{1}, List.of(new byte[]{2}), "s", Instant.now(), Instant.now(), "f"));
        EnrollmentRecord i = store.createSubmitting("req-i2", "caller-1", "idem-i", CSR, CSR_SHA, "TBOX_IDENTITY");
        assertEquals("req-i", i.requestId());
        assertEquals(EnrollmentState.ISSUED, i.state());
    }

    @Test
    void createSubmitting_shouldNotDoubleSign_onConcurrentRetry() throws Exception {
        flush();
        // 预置 FAILED 终态：并发重试同 key
        store.createSubmitting("req-old", "caller-1", "idem-cc", CSR, CSR_SHA, "TBOX_IDENTITY");
        store.markTerminal("req-old", EnrollmentState.FAILED, "failed");

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<EnrollmentRecord>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final String rid = "req-cc-" + i;
            futures.add(pool.submit(() -> {
                start.await();
                return store.createSubmitting(rid, "caller-1", "idem-cc", CSR, CSR_SHA, "TBOX_IDENTITY");
            }));
        }
        start.countDown();

        Set<String> returnedRequestIds = new HashSet<>();
        for (Future<EnrollmentRecord> f : futures) {
            returnedRequestIds.add(f.get(10, TimeUnit.SECONDS).requestId());
        }
        pool.shutdownNow();

        // 所有线程必须收敛到同一个获胜 requestId（Lua 原子槽位），杜绝并发双签
        assertEquals(1, returnedRequestIds.size(), "并发重试必须只有一个请求获得槽位: " + returnedRequestIds);
        String winner = returnedRequestIds.iterator().next();
        assertEquals(winner, store.findByIdempotency("caller-1", "idem-cc").orElseThrow().requestId());
        assertEquals(EnrollmentState.SUBMITTING, store.findByRequestId(winner).orElseThrow().state());
        assertTrue(store.findByRequestId("req-old").isPresent(), "旧 FAILED 记录保留");
    }

    @Test
    void findByRequestId_shouldExpireAfterTtl() throws Exception {
        flush();
        RedisCertificateEnrollmentResultStore shortTtl =
                new RedisCertificateEnrollmentResultStore(redisTemplate, Duration.ofSeconds(1));
        shortTtl.createSubmitting("req-ttl", "caller-1", "idem-ttl", CSR, CSR_SHA, "TBOX_IDENTITY");

        assertEquals(Optional.of("req-ttl"),
                shortTtl.findByIdempotency("caller-1", "idem-ttl").map(EnrollmentRecord::requestId));

        Thread.sleep(2_000);
        assertEquals(Optional.empty(), shortTtl.findByRequestId("req-ttl"));
        assertEquals(Optional.empty(), shortTtl.findByIdempotency("caller-1", "idem-ttl"));
    }
}
