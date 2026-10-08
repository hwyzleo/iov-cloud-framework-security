package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.util.Map;

/**
 * 封装上下文（FW-SEC-DSN-CR-009 §3）。
 *
 * @param mode          封装模式（可与收方推导不一致时 fail-closed；null 表示由收方推导）
 * @param idempotencyKey 幂等键
 * @param auditContext  审计上下文摘要（不含秘密）
 */
public record WrapContext(
        WrapMode mode,
        String idempotencyKey,
        Map<String, String> auditContext) implements Serializable {
}
