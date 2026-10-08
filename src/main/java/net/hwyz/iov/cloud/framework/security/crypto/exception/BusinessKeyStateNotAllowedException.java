package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 业务密钥状态不允许（FW-SEC-DSN-CR-009 §11）。
 * <p>
 * REVOKED/EXPIRED 或 DEPRECATED 已超解密窗口时抛出；信封头业务版本与目录不一致亦拒绝。
 */
public class BusinessKeyStateNotAllowedException extends CryptoException {

    public BusinessKeyStateNotAllowedException(String message) {
        super(Reason.BUSINESS_KEY_STATE_NOT_ALLOWED, message);
    }

    public BusinessKeyStateNotAllowedException(String message, Throwable cause) {
        super(Reason.BUSINESS_KEY_STATE_NOT_ALLOWED, message, cause);
    }
}
