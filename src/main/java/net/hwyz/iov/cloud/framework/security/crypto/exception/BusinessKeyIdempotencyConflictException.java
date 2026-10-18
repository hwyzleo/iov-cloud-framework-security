package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 业务密钥幂等冲突（FW-SEC-DSN-CR-009 §11）。
 * <p>
 * 同一幂等键对应不同请求摘要时 fail-closed，不得换键重建。
 */
public class BusinessKeyIdempotencyConflictException extends CryptoException {

    public BusinessKeyIdempotencyConflictException(String message) {
        super(Reason.BUSINESS_KEY_IDEMPOTENCY_CONFLICT, message);
    }

    public BusinessKeyIdempotencyConflictException(String message, Throwable cause) {
        super(Reason.BUSINESS_KEY_IDEMPOTENCY_CONFLICT, message, cause);
    }

    /**
     * 幂等冲突为确定性失败，不可重试（FW-SEC-DSN-CR-014 §7.2）。
     */
    @Override
    public boolean isRetryable() {
        return false;
    }
}
