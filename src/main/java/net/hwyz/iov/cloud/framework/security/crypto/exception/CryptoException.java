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
        PKI_DEPENDENCY_UNAVAILABLE
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
