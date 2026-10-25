package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.exception.DerivedWrapIdempotencyConflictException;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * InMemory {@link OperationResultStore}（FW-SEC-DSN-CR-020 §4）。
 * <p>
 * 进程内 {@code ConcurrentHashMap} 实现：懒 TTL 清理（读取时检查过期并删除）、
 * 终态清理（{@code markTerminal} 删除完整信封，保留非敏感摘要审计由上层日志负责）、
 * 同 operationId 不同请求摘要 → {@link DerivedWrapIdempotencyConflictException}。
 * <p>
 * 状态机语义（FW-SEC-DSN-CR-014 §6）：
 * <ul>
 *   <li>SUCCEEDED / PROCESSING 且摘要相同 → 返回原记录（原字节重放；PROCESSING 由 Provider
 *       按结果未知/不允许二次密码操作处理）；</li>
 *   <li>FAILED / OUTCOME_UNKNOWN 且摘要相同 → 允许重试覆盖（重新派生并保存新记录）；</li>
 *   <li>摘要不同 → 幂等冲突。</li>
 * </ul>
 * <strong>适用范围</strong>：单实例开发、单元测试与联调；<strong>不能</strong>支撑生产
 * capability READY——进程重启丢失、多实例不共享、无原子跨节点写入，违反 CR-020
 * 「返回原信封字节、不得重新编码/重新加密」要求。生产必须配置共享、持久化、原子写入的
 * Result Store（VMD 持久化实现或后续 Redis 实现）；在持久化实现落地前，生产
 * {@code EXTERNAL_AAD_PROFILE_V1} 保持 DOWN（FW-SEC-DSN-CR-020 §5/§8）。
 */
public class InMemoryOperationResultStore implements OperationResultStore {

    public static final String STORE_TYPE = "in-memory";

    private final Map<String, DerivedWrapResultRecord> records = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryOperationResultStore() {
        this(Clock.systemUTC());
    }

    public InMemoryOperationResultStore(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public Optional<DerivedWrapResultRecord> find(String operationId) {
        if (operationId == null) {
            return Optional.empty();
        }
        DerivedWrapResultRecord record = records.get(operationId);
        if (record == null) {
            return Optional.empty();
        }
        if (!record.expiresAt().isAfter(clock.instant())) {
            // TTL 到期：终态清理完整信封
            records.remove(operationId);
            return Optional.empty();
        }
        return Optional.of(record);
    }

    @Override
    public DerivedWrapResultRecord save(DerivedWrapResultRecord record) {
        Objects.requireNonNull(record, "record must not be null");
        DerivedWrapResultRecord previous = records.putIfAbsent(record.operationId(), record);
        if (previous == null) {
            return record;
        }
        if (!previous.requestDigestHex().equals(record.requestDigestHex())) {
            throw new DerivedWrapIdempotencyConflictException(
                    "operationId=" + record.operationId()
                            + " 已存在且请求摘要不同（profile/hash 变化），返回幂等冲突"
                            + "（FW-SEC-DSN-CR-020 §4）");
        }
        if (previous.status() == DerivedWrapResultRecord.Status.SUCCEEDED
                || previous.status() == DerivedWrapResultRecord.Status.PROCESSING
                || previous.status() == DerivedWrapResultRecord.Status.NEW) {
            // 原字节重放语义：不得覆盖已受理/成功的原记录
            return previous;
        }
        // FAILED / OUTCOME_UNKNOWN：允许按原 operationId 重试覆盖
        records.put(record.operationId(), record);
        return record;
    }

    @Override
    public void markTerminal(String operationId, DerivedWrapResultRecord.Status status,
                             String failReason) {
        if (operationId == null) {
            return;
        }
        records.remove(operationId);
    }

    @Override
    public boolean productionReady() {
        // InMemory 无法覆盖进程重启、多实例路由与滚动发布：不支撑生产 READY
        return false;
    }

    @Override
    public String storeType() {
        return STORE_TYPE;
    }
}
