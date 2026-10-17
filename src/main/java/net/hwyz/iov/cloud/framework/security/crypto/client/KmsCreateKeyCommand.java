package net.hwyz.iov.cloud.framework.security.crypto.client;

import java.time.Instant;

/**
 * KMS 创建业务密钥材料命令（FW-SEC-DSN-CR-009 §9；FW-SEC-DSN-CR-011 §6.1）。
 * <p>
 * Provider Adapter 负责把 OpenBao business-key Provider、云 KMS/HSM 等差异映射为统一对象；
 * 业务方不需要理解 provider 路径、Transit key name、云厂商版本号或 token。
 * <p>
 * 写操作必须携带客户端生成的 {@code operationId}（UUIDv7），用于结果未知时按原 operationId 对账。
 *
 * @param bizType            业务类型名（治理语义，仅用于本地审计/指标，不进入 wire）
 * @param operationId        客户端生成的 UUIDv7 操作标识（对账主键）
 * @param idempotencyKey     幂等键（结果未知时须使用原键对账）
 * @param algorithm          算法
 * @param keySpec            密钥规格
 * @param validFrom          生效时间（可空，由 Provider 决定）
 * @param validTo            失效时间（可空）
 * @param auditContextDigest 审计上下文摘要（规范化请求 SHA-256，不含秘密）
 */
public record KmsCreateKeyCommand(
        String bizType,
        String operationId,
        String idempotencyKey,
        String algorithm,
        String keySpec,
        Instant validFrom,
        Instant validTo,
        String auditContextDigest) {
}
