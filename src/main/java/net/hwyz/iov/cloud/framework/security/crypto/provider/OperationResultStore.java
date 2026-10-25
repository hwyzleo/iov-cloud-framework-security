package net.hwyz.iov.cloud.framework.security.crypto.provider;

import java.util.Optional;

/**
 * 派生封装 operation 结果存储 SPI（FW-SEC-DSN-CR-020 §4；FW-SEC-DSN-CR-014 §6）。
 * <p>
 * Provider 在「受控边界」内持久化 {@link DerivedWrapResultRecord}，实现：
 * <ul>
 *   <li><strong>字节级幂等重放</strong>：相同 {@code operationId} + 相同请求摘要返回原信封
 *       （重放不得重新调用 encoder、随机源或 Transit）；</li>
 *   <li><strong>幂等冲突</strong>：相同 operation 但请求摘要（profile/hash）变化 → 冲突；</li>
 *   <li><strong>结果未知对账</strong>：PROCESSING/OUTCOME_UNKNOWN 状态供对账；</li>
 *   <li><strong>TTL 与终态清理</strong>：信封 TTL 至少覆盖请求有效期、设备 ACK 窗口及对账窗口；
 *       终态/到期后清理完整信封，保留必要非敏感摘要审计。</li>
 * </ul>
 * <strong>生产约束</strong>：完整密文信封属于「限定允许」持久化，实现方必须
 * 加密存储、最小权限、TTL 与终态清理（CR-014 §6）。InMemory 实现仅用于单实例开发、
 * 单测和联调；生产 capability（{@code EXTERNAL_AAD_PROFILE_V1}）要求共享、持久化、
 * 原子写入的 Result Store（{@link #productionReady()} 返回 true），InMemory 在未显式
 * 允许 dev/test 时不得支撑生产 READY（FW-SEC-DSN-CR-020 §5）。
 */
public interface OperationResultStore {

    /**
     * 按 operationId 读取原记录（含终态/对账语义）。
     *
     * @param operationId 对账主键
     * @return 记录；不存在或已过期清理返回 empty
     */
    Optional<DerivedWrapResultRecord> find(String operationId);

    /**
     * 保存记录（幂等 upsert）。
     * <p>
     * 若 operationId 已存在且 {@code requestDigestHex} 不同 → 抛
     * {@code DerivedWrapIdempotencyConflictException}（相同 operation 但 profile/hash 变化）；
     * 相同摘要的重复保存幂等返回原记录语义（不得覆盖已 SUCCEEDED 的原字节）。
     *
     * @param record 记录
     * @return 保存后的记录
     */
    DerivedWrapResultRecord save(DerivedWrapResultRecord record);

    /**
     * 标记终态（SUCCEEDED/FAILED/OUTCOME_UNKNOWN），按策略清理完整信封、保留非敏感摘要。
     *
     * @param operationId 操作标识
     * @param status      终态
     * @param failReason  失败 reason（终态 SUCCEEDED 时为 null）
     */
    void markTerminal(String operationId, DerivedWrapResultRecord.Status status, String failReason);

    /**
     * 是否可支撑生产 capability READY（共享、持久化、原子写入）。
     * <p>InMemory 返回 {@code false}；持久化实现（Redis/VMD 提供）返回 {@code true}。</p>
     */
    boolean productionReady();

    /**
     * 存储类型标识（如 {@code in-memory} / {@code persistent}），供 readiness/日志区分。
     */
    String storeType();
}
