package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 业务密钥目录不可用（FW-SEC-DSN-CR-009 §11）。
 * <p>
 * 正反向寻址失败（目录拒绝/越权/空/多值/状态不一致/不可达）时抛出。
 * 目录不可用不得降级为直接按 KMS keyId 取钥解密（RD-009-6）。
 */
public class BusinessKeyDirectoryUnavailableException extends CryptoException {

    public BusinessKeyDirectoryUnavailableException(String message) {
        super(Reason.BUSINESS_KEY_DIRECTORY_UNAVAILABLE, message);
    }

    public BusinessKeyDirectoryUnavailableException(String message, Throwable cause) {
        super(Reason.BUSINESS_KEY_DIRECTORY_UNAVAILABLE, message, cause);
    }
}
