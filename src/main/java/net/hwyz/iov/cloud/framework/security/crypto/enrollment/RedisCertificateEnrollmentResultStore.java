package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Redis 证书注册结果存储（FW-SEC-DSN-CR-008 §5.1）
 * <p>
 * 生产默认实现：共享且可恢复。记录按 requestId 键控并维护 caller:idempotencyKey 索引；
 * 两者均带 TTL（不短于业务补偿窗口）。幂等索引以 SETNX 原子创建，防并发双签。
 * <p>
 * 证书材料非私钥，但仍按安全数据管理：不输出普通日志；静态加密依赖 Redis 侧配置。
 */
public class RedisCertificateEnrollmentResultStore implements CertificateEnrollmentResultStore {

    private static final String RECORD_KEY_PREFIX = "fwsec:enrollment:rec:";
    private static final String IDEM_KEY_PREFIX = "fwsec:enrollment:idx:";

    /**
     * 原子获取幂等槽位（FW-SEC-DSN-CR-008 §5.1）：读索引 → 判终态 → 覆盖/新建 → 写记录，全部在一个
     * Redis 脚本内完成，杜绝并发重试各自覆盖索引导致的同 CSR 双签。
     * <ul>
     *   <li>索引不存在或已指向本 requestId → 创建；</li>
     *   <li>索引指向可重试终态（FAILED/REJECTED）→ 覆盖索引并创建新记录（旧记录保留）；</li>
     *   <li>否则（ISSUED/UNKNOWN/进行中）→ 返回既有 requestId，不新建、不覆盖。</li>
     * </ul>
     * 返回 {{@code 1, requestId}}（获得槽位）或 {{@code 0, existingId}}（未获得）。
     * 注意：脚本内联的 {@code fwsec:enrollment:rec:} 前缀必须与 {@link #RECORD_KEY_PREFIX} 保持一致。
     */
    private static final DefaultRedisScript<List> ACQUIRE_SLOT_SCRIPT = new DefaultRedisScript<>("""
            local existingId = redis.call('GET', KEYS[1])
            if existingId and existingId ~= ARGV[1] then
              local existingJson = redis.call('GET', 'fwsec:enrollment:rec:' .. existingId)
              if existingJson then
                local ok, obj = pcall(cjson.decode, existingJson)
                if ok and obj then
                  local st = obj['state']
                  if not (st == 'FAILED' or st == 'REJECTED') then
                    return {0, existingId}
                  end
                end
              end
            end
            redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
            redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
            return {1, ARGV[1]}
            """, List.class);

    private final StringRedisTemplate redis;
    private final Duration ttl;
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    public RedisCertificateEnrollmentResultStore(StringRedisTemplate redis, Duration ttl) {
        this.redis = redis;
        this.ttl = ttl == null ? Duration.ofDays(30) : ttl;
    }

    @Override
    public Optional<EnrollmentRecord> findByRequestId(String requestId) {
        String json = redis.opsForValue().get(recordKey(requestId));
        if (json == null) {
            return Optional.empty();
        }
        return Optional.of(deserialize(json));
    }

    @Override
    public Optional<EnrollmentRecord> findByIdempotency(String caller, String idempotencyKey) {
        String requestId = redis.opsForValue().get(idemKey(caller, idempotencyKey));
        if (requestId == null) {
            return Optional.empty();
        }
        return findByRequestId(requestId);
    }

    @Override
    public EnrollmentRecord createSubmitting(String requestId, String caller, String idempotencyKey,
                                             byte[] csr, String csrSha256, String profileName) {
        Instant now = Instant.now();
        EnrollmentRecord record = new EnrollmentRecord(requestId, caller, idempotencyKey, csr, csrSha256,
                profileName, EnrollmentState.SUBMITTING, null, null, null, null, null, null, null, now, now);
        long ttlSeconds = Math.max(1, ttl.toSeconds());
        List<Object> result = redis.execute(ACQUIRE_SLOT_SCRIPT,
                List.of(idemKey(caller, idempotencyKey), recordKey(requestId)),
                requestId, serialize(record), Long.toString(ttlSeconds));
        boolean acquired = result != null && result.size() >= 1
                && result.get(0) instanceof Number n && n.longValue() == 1L;
        if (acquired) {
            return record;
        }
        // 未获得槽位：返回既有记录（并发/非可重试终态），不重复写入
        String existingId = result != null && result.size() >= 2
                ? String.valueOf(result.get(1)) : requestId;
        return findByRequestId(existingId).orElseThrow(() ->
                new IllegalStateException("Idempotency index exists but record is missing: " + existingId));
    }

    @Override
    public EnrollmentRecord save(EnrollmentRecord record) {
        redis.opsForValue().set(recordKey(record.requestId()), serialize(record), ttl);
        redis.opsForValue().set(idemKey(record.caller(), record.idempotencyKey()), record.requestId(), ttl);
        return record;
    }

    @Override
    public void markIssued(String requestId, IssuedCertificate certificate) {
        findByRequestId(requestId).ifPresent(record -> {
            EnrollmentRecord issued = new EnrollmentRecord(
                    record.requestId(), record.caller(), record.idempotencyKey(), record.csr(),
                    record.csrSha256(), record.profileName(), EnrollmentState.ISSUED,
                    certificate.serialNumber(), certificate.leafCertificate(), certificate.certificateChain(),
                    certificate.notBefore().toString(), certificate.notAfter().toString(),
                    certificate.sha256Fingerprint(), null, record.createdAt(), Instant.now());
            redis.opsForValue().set(recordKey(requestId), serialize(issued), ttl);
        });
    }

    @Override
    public void markTerminal(String requestId, EnrollmentState state, String errorSummary) {
        findByRequestId(requestId).ifPresent(record -> {
            EnrollmentRecord terminal = record.withState(state).withErrorSummary(errorSummary);
            redis.opsForValue().set(recordKey(requestId), serialize(terminal), ttl);
        });
    }

    @Override
    public void markUnknown(String requestId, String errorSummary) {
        markTerminal(requestId, EnrollmentState.UNKNOWN, errorSummary);
    }

    private String recordKey(String requestId) {
        return RECORD_KEY_PREFIX + requestId;
    }

    private String idemKey(String caller, String idempotencyKey) {
        return IDEM_KEY_PREFIX + caller + ":" + idempotencyKey;
    }

    private String serialize(EnrollmentRecord record) {
        try {
            return objectMapper.writeValueAsString(record);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize enrollment record", e);
        }
    }

    private EnrollmentRecord deserialize(String json) {
        try {
            return objectMapper.readValue(json, EnrollmentRecord.class);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize enrollment record", e);
        }
    }
}
