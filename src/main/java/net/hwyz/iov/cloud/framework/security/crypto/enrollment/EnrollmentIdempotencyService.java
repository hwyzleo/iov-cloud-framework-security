package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;

import java.util.Objects;
import java.util.Optional;

/**
 * 证书申请幂等服务（FW-SEC-DSN-CR-008 §5.2 / §6）
 * <p>
 * 基于结果存储的幂等语义：
 * <ul>
 *   <li>同 key 完全一致（CSR SHA-256、profile 相同）→ 返回既有记录，不重复签发；</li>
 *   <li>同 key 参数不同 → 抛 {@link CertificateIdempotencyConflictException}；</li>
 *   <li>既有记录为 UNKNOWN → 返回 UNKNOWN，不自动重新签发（运维受控恢复）。</li>
 * </ul>
 */
public class EnrollmentIdempotencyService {

    private final CertificateEnrollmentResultStore resultStore;

    public EnrollmentIdempotencyService(CertificateEnrollmentResultStore resultStore) {
        this.resultStore = Objects.requireNonNull(resultStore, "resultStore must not be null");
    }

    /**
     * 幂等查询。
     *
     * @param caller          调用方标识（结果存储按 caller 隔离幂等域）
     * @param idempotencyKey  幂等键
     * @param csr             本次提交的 CSR
     * @param profileName     本次提交的 profile 名
     * @return 存在且参数一致的既有记录；不存在返回 empty；参数不一致抛冲突异常
     */
    public Optional<EnrollmentRecord> findExisting(String caller, String idempotencyKey,
                                                   byte[] csr, String profileName) {
        Optional<EnrollmentRecord> existing = resultStore.findByIdempotency(caller, idempotencyKey);
        if (existing.isEmpty()) {
            return Optional.empty();
        }
        EnrollmentRecord record = existing.get();
        String csrSha256 = EnrollmentRecord.sha256Hex(csr);
        if (!record.csrSha256().equals(csrSha256) || !record.profileName().equals(profileName)) {
            throw new CertificateIdempotencyConflictException(
                    "Idempotency key already used with different CSR or profile: caller=" + caller
                            + ", idempotencyKey=" + idempotencyKey
                            + ", existingProfile=" + record.profileName()
                            + ", newProfile=" + profileName);
        }
        return existing;
    }

    /**
     * 判断既有记录是否为未知结果终态（禁止自动重签）。
     */
    public static boolean isUnknownOutcome(EnrollmentRecord record) {
        return record.state() == EnrollmentState.UNKNOWN;
    }

    /**
     * 判断既有记录是否为可重试终态（FAILED/REJECTED）。
     * <p>
     * 「失败可重试」业务语义：FAILED（framework 侧校验/依赖失败）与 REJECTED（CA 4xx 拒绝）
     * 均未产生证书，允许以同 idempotencyKey 重新申请；UNKNOWN（请求已发送、结果未知）与
     * ISSUED/进行中禁止重签（防双签）。
     */
    public static boolean isRetryableTerminal(EnrollmentRecord record) {
        return record.state() == EnrollmentState.FAILED
                || record.state() == EnrollmentState.REJECTED;
    }
}
