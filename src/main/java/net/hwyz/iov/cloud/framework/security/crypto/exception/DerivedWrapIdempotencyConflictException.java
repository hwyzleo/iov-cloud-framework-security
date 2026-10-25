package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 派生封装幂等冲突（FW-SEC-DSN-CR-020 §4；FW-SEC-DSN-CR-014 §5.2/§7.2）。
 * <p>
 * 相同 {@code operationId} 但请求摘要（aadProfileId / 证书 / 版本 / 套件等）变化：
 * 确定性、不可重试（同键不同输入必须拒绝，不得以新输入重建或覆盖原记录）。
 * 对应 {@code CryptoException.Reason.IDEMPOTENCY_CONFLICT}。
 */
public class DerivedWrapIdempotencyConflictException extends CryptoException {

    public DerivedWrapIdempotencyConflictException(String message) {
        super(CryptoException.Reason.IDEMPOTENCY_CONFLICT, message);
    }

    public DerivedWrapIdempotencyConflictException(String message, Throwable cause) {
        super(CryptoException.Reason.IDEMPOTENCY_CONFLICT, message, cause);
    }

    @Override
    public boolean isRetryable() {
        return false;
    }
}
