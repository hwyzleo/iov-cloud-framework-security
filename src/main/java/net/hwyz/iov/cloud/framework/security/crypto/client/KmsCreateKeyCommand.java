package net.hwyz.iov.cloud.framework.security.crypto.client;

import java.util.Map;

/**
 * KMS 创建业务密钥材料命令（FW-SEC-DSN-CR-009 §9）。
 * <p>
 * Provider Adapter 负责把 OpenBao Transit、云 KMS/HSM 等差异映射为统一对象；
 * 业务方不需要理解 provider 路径、Transit key name、云厂商版本号或 token。
 *
 * @param bizType        业务类型名（治理语义，非材料主键）
 * @param algorithm      算法
 * @param keySpec        密钥规格
 * @param idempotencyKey 幂等键（结果未知时须使用原键对账）
 * @param auditContext   审计上下文摘要（不含秘密）
 */
public record KmsCreateKeyCommand(
        String bizType,
        String algorithm,
        String keySpec,
        String idempotencyKey,
        Map<String, String> auditContext) {
}
