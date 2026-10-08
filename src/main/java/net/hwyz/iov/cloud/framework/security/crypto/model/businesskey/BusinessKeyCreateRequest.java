package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;

import java.io.Serializable;
import java.util.Map;
import java.util.Objects;

/**
 * 业务密钥材料创建请求（FW-SEC-DSN-CR-009 §3）。
 * <p>
 * 约束：不接收 VIN、deviceSn、businessDomain、purpose 或 businessKeyVersion；
 * 这些只进入 VMD 业务关系和审计上下文摘要，framework 不以其作为材料主键。
 *
 * @param bizType        业务类型（材料治理语义）
 * @param policy         密钥材料策略（算法 / 规格）
 * @param idempotencyKey 幂等键（结果未知时须使用原键对账，不得换键重建）
 * @param auditContext   审计上下文摘要（不得含明文密钥）
 */
public record BusinessKeyCreateRequest(
        BizType bizType,
        KeyMaterialPolicy policy,
        String idempotencyKey,
        Map<String, String> auditContext) implements Serializable {

    public BusinessKeyCreateRequest {
        Objects.requireNonNull(bizType, "bizType must not be null");
        Objects.requireNonNull(policy, "policy must not be null");
    }
}
