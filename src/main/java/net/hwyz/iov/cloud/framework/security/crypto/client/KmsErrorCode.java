package net.hwyz.iov.cloud.framework.security.crypto.client;

/**
 * 业务密钥 Provider 统一错误体 code（FW-SEC-DSN-CR-011 §6）。
 * <p>
 * 仅用于把 Provider 结构化错误分类为 framework 类型化异常；framework 仍然不对外定义错误码。
 * 非契约错误体（HTML、OpenBao 原生 {@code {"errors":[...]}}、无 code）一律解析为 {@link #UNKNOWN}。
 */
public enum KmsErrorCode {
    SUCCESS,
    BUSINESS_KEY_NOT_FOUND,
    IDEMPOTENCY_CONFLICT,
    PROVIDER_NOT_READY,
    OPERATION_OUTCOME_UNKNOWN,
    INVALID_REQUEST,
    UNSUPPORTED_ALGORITHM,
    UNAUTHENTICATED,
    FORBIDDEN,
    BUSINESS_KEY_REVOKED,
    BUSINESS_KEY_EXPIRED,
    RATE_LIMITED,
    PROVIDER_ERROR,
    NOT_READY,
    UNKNOWN;

    /**
     * 解析 wire code；空值或未知值统一返回 {@link #UNKNOWN}（fail-closed，不猜测）。
     */
    public static KmsErrorCode fromWire(String code) {
        if (code == null || code.isBlank()) {
            return UNKNOWN;
        }
        try {
            return valueOf(code.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}
