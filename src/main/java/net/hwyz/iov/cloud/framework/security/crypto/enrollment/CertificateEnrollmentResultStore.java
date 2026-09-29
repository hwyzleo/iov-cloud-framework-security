package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;

import java.util.Optional;

/**
 * 证书注册结果存储 SPI（FW-SEC-DSN-CR-008 §5.1）
 * <p>
 * 适配 step-ca 同步签发无 requestId/status/certificate 三段式契约的语义：
 * framework 生成稳定 requestId，签发结果原子写入本存储，status/certificate 从本存储读取。
 * <p>
 * 生产实现必须共享且可恢复（如 Redis）；进程内有界实现仅用于开发/测试。
 * 该存储是 enrollment 交付记录，不取代 PKI 的 CA/吊销/生命周期权威。
 */
public interface CertificateEnrollmentResultStore {

    /**
     * 按 requestId 查询记录。
     */
    Optional<EnrollmentRecord> findByRequestId(String requestId);

    /**
     * 按调用方 + 幂等键查询记录。
     */
    Optional<EnrollmentRecord> findByIdempotency(String caller, String idempotencyKey);

    /**
     * 原子写入 SUBMITTING 记录。
     * <p>
     * 幂等索引已存在时：
     * <ul>
     *   <li>索引指向的记录为可重试终态（FAILED/REJECTED）→ 覆盖索引并以新 requestId 新建记录，
     *       旧终态记录保留供审计（FW-SEC-DSN-CR-008 失败可重试语义）；</li>
     *   <li>否则（ISSUED/UNKNOWN/进行中）→ 返回既有记录，不重复写入、不重签。</li>
     * </ul>
     *
     * @return 写入（或已存在）的记录
     */
    EnrollmentRecord createSubmitting(String requestId, String caller, String idempotencyKey,
                                      byte[] csr, String csrSha256, String profileName);

    /**
     * 覆盖保存记录（upsert，legacy-rest 在 submit 后回写状态/CSR 用）。
     */
    EnrollmentRecord save(EnrollmentRecord record);

    /**
     * 原子标记为 ISSUED 并写入证书材料。
     */
    void markIssued(String requestId, IssuedCertificate certificate);

    /**
     * 原子标记为终态（REJECTED/FAILED），仅记录去敏错误摘要。
     */
    void markTerminal(String requestId, EnrollmentState state, String errorSummary);

    /**
     * 原子标记为 UNKNOWN（请求已发送但响应丢失），仅记录去敏错误摘要。
     */
    void markUnknown(String requestId, String errorSummary);
}
