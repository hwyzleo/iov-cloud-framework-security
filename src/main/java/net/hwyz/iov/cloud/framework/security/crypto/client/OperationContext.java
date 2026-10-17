package net.hwyz.iov.cloud.framework.security.crypto.client;

import java.util.Objects;

/**
 * 写操作上下文（FW-SEC-DSN-CR-013 §7.3；FW-SEC-DSN-CR-011 §6.5/§10）。
 * <p>
 * {@code operationId} 为客户端生成的 UUIDv7 对账主键；{@code idempotencyKey} 为 Provider 服务端
 * 幂等作用域键。请求已发送后超时/5xx 一律按结果未知处理，调用方须使用原 operationId/幂等键对账，
 * 不得换键重建。
 *
 * @param operationId    客户端生成的 UUIDv7 操作标识（对账主键）
 * @param idempotencyKey 幂等键（相同键 + 相同请求摘要返回同一逻辑结果）
 */
public record OperationContext(String operationId, String idempotencyKey) {

    public OperationContext {
        Objects.requireNonNull(operationId, "operationId must not be null");
        if (operationId.isBlank()) {
            throw new IllegalArgumentException("operationId must not be blank");
        }
        Objects.requireNonNull(idempotencyKey, "idempotencyKey must not be null");
        if (idempotencyKey.isBlank()) {
            throw new IllegalArgumentException("idempotencyKey must not be blank");
        }
    }
}
