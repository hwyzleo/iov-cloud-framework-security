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
        CRYPTO_OPERATION_OUTCOME_UNKNOWN,
        // 密钥材料模型路由与根派生契约（FW-SEC-DSN-CR-013 §7.3/§6）
        MATERIAL_MODEL_MISMATCH,
        INVALID_KEY_ANCHOR,
        UNSUPPORTED_RECIPIENT,
        LEGACY_FACADE_UNSUPPORTED,
        // 证书材料解析（FW-SEC-DSN-CR-012 §5/§6）
        CERTIFICATE_EVIDENCE_MISMATCH,
        CERTIFICATE_REFERENCE_AMBIGUOUS,
        CERTIFICATE_MATERIAL_UNAVAILABLE,
        // 证书策略拒绝（FW-SEC-DSN-CR-014 §7.2）：确定性、不可重试
        CERTIFICATE_EVIDENCE_REJECTED,
        // 证书状态/吊销查询（FW-SEC-DSN-CR-010 §7）
        CERTIFICATE_STATUS_DEPENDENCY_UNAVAILABLE,
        CERTIFICATE_STATUS_TRUST_VALIDATION_FAILED,
        CERTIFICATE_STATUS_PROTOCOL_ERROR,
        CERTIFICATE_STATUS_CONFIGURATION_INVALID,
        CERTIFICATE_STATUS_OUTCOME_UNKNOWN
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

    /**
     * 该异常是否表示「可按预算重试」的瞬时失败（FW-SEC-DSN-CR-014 §7.2）。
     * <p>
     * 默认 {@code true}（材料/依赖暂时不可用）；证书策略拒绝、幂等冲突等确定性失败
     * 覆写为 {@code false}，业务服务不得把此类异常标为可重试。
     *
     * @return true 表示可重试
     */
    public boolean isRetryable() {
        return true;
    }
}
