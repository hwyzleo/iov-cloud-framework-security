package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 密码学操作结果未知（FW-SEC-DSN-CR-009 §11）。
 * <p>
 * 请求已发送但结果无法确认（超时、中断、5xx）时抛出；调用方必须使用原幂等键对账，
 * 不得换键重建；framework 不得在超时后自动把密钥标记为可用。
 */
public class CryptoOperationOutcomeUnknownException extends CryptoException {

    private final String operationId;

    public CryptoOperationOutcomeUnknownException(String message) {
        this(message, null, null);
    }

    public CryptoOperationOutcomeUnknownException(String message, Throwable cause) {
        this(message, cause, null);
    }

    /**
     * @param operationId 客户端生成的 UUIDv7 操作标识；调用方须以原 operationId/幂等键对账
     */
    public CryptoOperationOutcomeUnknownException(String message, Throwable cause, String operationId) {
        super(Reason.CRYPTO_OPERATION_OUTCOME_UNKNOWN, message, cause);
        this.operationId = operationId;
    }

    /**
     * 用于对账的 operationId；未携带时为 null。
     */
    public String getOperationId() {
        return operationId;
    }
}
