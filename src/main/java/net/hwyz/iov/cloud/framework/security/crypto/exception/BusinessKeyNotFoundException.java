package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 业务密钥不存在（FW-SEC-DSN-CR-009 §11）。
 * <p>
 * 目录或显式 keyRef 不存在时抛出。
 */
public class BusinessKeyNotFoundException extends CryptoException {

    public BusinessKeyNotFoundException(String message) {
        super(Reason.BUSINESS_KEY_NOT_FOUND, message);
    }

    public BusinessKeyNotFoundException(String message, Throwable cause) {
        super(Reason.BUSINESS_KEY_NOT_FOUND, message, cause);
    }
}
