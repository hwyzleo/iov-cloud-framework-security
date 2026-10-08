package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 业务密钥吊销失败（FW-SEC-DSN-CR-009 §11）。
 * <p>
 * 显式 keyRef 吊销失败时抛出；结果未知须抛 {@link CryptoOperationOutcomeUnknownException}。
 */
public class BusinessKeyRevocationFailedException extends CryptoException {

    public BusinessKeyRevocationFailedException(String message) {
        super(Reason.BUSINESS_KEY_REVOCATION_FAILED, message);
    }

    public BusinessKeyRevocationFailedException(String message, Throwable cause) {
        super(Reason.BUSINESS_KEY_REVOCATION_FAILED, message, cause);
    }
}
