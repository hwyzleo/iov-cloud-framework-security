package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书申请幂等冲突异常（FW-SEC-DSN-CR-008 §5.2）
 * <p>
 * 相同 idempotencyKey 再次提交但 CSR 或 profile 与既有申请不一致时抛出；
 * 禁止静默覆盖或重新签发，必须由调用方换 key 重新申请。
 */
public class CertificateIdempotencyConflictException extends CryptoException {

    public CertificateIdempotencyConflictException(String message) {
        super(Reason.IDEMPOTENCY_CONFLICT, message);
    }

    public CertificateIdempotencyConflictException(String message, Throwable cause) {
        super(Reason.IDEMPOTENCY_CONFLICT, message, cause);
    }
}
