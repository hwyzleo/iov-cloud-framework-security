package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 加解密异常基类
 */
public abstract class CryptoException extends RuntimeException {

    private final Reason reason;

    public enum Reason {
        DEVICE_UNBOUND,
        DEPENDENCY_UNAVAILABLE,
        KEY_REVOKED,
        INTEGRITY_VERIFICATION_FAILED,
        INVALID_BIZ_TYPE,
        INVALID_CERTIFICATE_REQUEST,
        CERTIFICATE_PROFILE_NOT_ALLOWED,
        CERTIFICATE_APPLICATION_REJECTED,
        CERTIFICATE_NOT_READY,
        PKI_DEPENDENCY_UNAVAILABLE,
        PKI_OUTCOME_UNKNOWN,
        IDEMPOTENCY_CONFLICT,
        BUSINESS_KEY_NOT_FOUND,
        BUSINESS_KEY_STATE_NOT_ALLOWED,
        BUSINESS_KEY_DIRECTORY_UNAVAILABLE,
        BUSINESS_KEY_IDEMPOTENCY_CONFLICT,
        BUSINESS_KEY_WRAP_FAILED,
        BUSINESS_KEY_REVOCATION_FAILED,
        CRYPTO_OPERATION_OUTCOME_UNKNOWN
    }

    public CryptoException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public CryptoException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
