package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 密码学操作结果未知（FW-SEC-DSN-CR-009 §11）。
 * <p>
 * 请求已发送但结果无法确认（超时、中断、5xx）时抛出；调用方必须使用原幂等键对账，
 * 不得换键重建；framework 不得在超时后自动把密钥标记为可用。
 */
public class CryptoOperationOutcomeUnknownException extends CryptoException {

    public CryptoOperationOutcomeUnknownException(String message) {
        super(Reason.CRYPTO_OPERATION_OUTCOME_UNKNOWN, message);
    }

    public CryptoOperationOutcomeUnknownException(String message, Throwable cause) {
        super(Reason.CRYPTO_OPERATION_OUTCOME_UNKNOWN, message, cause);
    }
}
