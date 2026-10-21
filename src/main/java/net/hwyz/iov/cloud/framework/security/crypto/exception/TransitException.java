package net.hwyz.iov.cloud.framework.security.crypto.exception;

import java.util.Objects;

/**
 * Transit 派生/封装失败（FW-SEC-DSN-CR-019 §10）。
 * <p>
 * 统一携带稳定 {@link TransitReason}（VMD 依赖，不解析异常正文）；继承
 * {@link CryptoException} 保持既有异常体系与 fail-closed 语义。失败信息不得包含
 * 派生明文、Transit HMAC 值、Token 或完整 Wrapped Key。
 */
public class TransitException extends CryptoException {

    private final TransitReason transitReason;

    public TransitException(TransitReason transitReason, String message) {
        super(CryptoException.Reason.TRANSIT_DERIVED_KEY, message);
        this.transitReason = Objects.requireNonNull(transitReason, "transitReason must not be null");
    }

    public TransitException(TransitReason transitReason, String message, Throwable cause) {
        super(CryptoException.Reason.TRANSIT_DERIVED_KEY, message, cause);
        this.transitReason = Objects.requireNonNull(transitReason, "transitReason must not be null");
    }

    /**
     * 稳定失败原因（VMD keyprov 依赖）。
     */
    public TransitReason transitReason() {
        return transitReason;
    }

    @Override
    public boolean isRetryable() {
        return transitReason.isRetryable();
    }

    // ==================== 静态工厂 ====================

    public static TransitException unavailable(String op, Throwable cause) {
        return new TransitException(TransitReason.TRANSIT_UNAVAILABLE,
                "Transit unavailable: " + op, cause);
    }

    public static TransitException unavailable(String op) {
        return new TransitException(TransitReason.TRANSIT_UNAVAILABLE,
                "Transit unavailable: " + op);
    }

    public static TransitException sealed(String op) {
        return new TransitException(TransitReason.TRANSIT_SEALED,
                "OpenBao transit sealed/uninitialized: " + op);
    }

    public static TransitException authFailed(String op) {
        return new TransitException(TransitReason.TRANSIT_AUTH_FAILED,
                "Transit authentication failed after re-authentication: " + op);
    }

    public static TransitException rootNotFound(String rootKeyName) {
        return new TransitException(TransitReason.TRANSIT_ROOT_NOT_FOUND,
                "Transit root key not found: " + rootKeyName);
    }

    public static TransitException rootTypeMismatch(String rootKeyName, String detail) {
        return new TransitException(TransitReason.TRANSIT_ROOT_TYPE_MISMATCH,
                "Transit root key type/configuration mismatch: " + rootKeyName + " (" + detail + ")");
    }

    public static TransitException hmacForbidden(String rootKeyName) {
        return new TransitException(TransitReason.TRANSIT_HMAC_FORBIDDEN,
                "Transit HMAC path forbidden: " + rootKeyName);
    }

    public static TransitException policyInvalid(String detail) {
        return new TransitException(TransitReason.DERIVATION_POLICY_INVALID,
                "Derivation policy invalid: " + detail);
    }

    public static TransitException recipientInvalid(String detail) {
        return new TransitException(TransitReason.RECIPIENT_CERTIFICATE_INVALID,
                "Recipient certificate final gate failed: " + detail);
    }

    public static TransitException wrapUnavailable(String detail, Throwable cause) {
        return new TransitException(TransitReason.WRAP_ALGORITHM_UNAVAILABLE,
                "Local wrap algorithm unavailable: " + detail, cause);
    }

    public static TransitException derivedKeyLength(int expected, int actual) {
        return new TransitException(TransitReason.DERIVED_KEY_LENGTH_INVALID,
                "Derived key material length invalid: expected " + expected + " bytes, got " + actual);
    }

    public static TransitException formatInvalid(String detail) {
        return new TransitException(TransitReason.DERIVED_KEY_FORMAT_INVALID,
                "Transit HMAC response format invalid: " + detail);
    }

    /**
     * 非敏感描述：只输出稳定 reason，不展开正文中的敏感细节。
     */
    @Override
    public String toString() {
        return "TransitException{transitReason=" + transitReason.wireName()
                + ", message=" + getMessage() + '}';
    }
}
