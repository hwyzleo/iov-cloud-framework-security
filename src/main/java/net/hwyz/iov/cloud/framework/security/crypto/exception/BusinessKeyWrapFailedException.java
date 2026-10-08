package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 业务密钥封装失败（FW-SEC-DSN-CR-009 §11）。
 * <p>
 * 指定材料无法按收方模式 Wrap（证书失效、ROOT 未登记、算法不支持、模式不一致等）时抛出。
 */
public class BusinessKeyWrapFailedException extends CryptoException {

    public BusinessKeyWrapFailedException(String message) {
        super(Reason.BUSINESS_KEY_WRAP_FAILED, message);
    }

    public BusinessKeyWrapFailedException(String message, Throwable cause) {
        super(Reason.BUSINESS_KEY_WRAP_FAILED, message, cause);
    }
}
