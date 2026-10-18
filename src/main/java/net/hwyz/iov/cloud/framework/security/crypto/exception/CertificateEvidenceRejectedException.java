package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书证据策略拒绝异常（FW-SEC-DSN-CR-014 §7.1/§7.2）。
 * <p>
 * 表示收方证书在某一<strong>确定性固有属性</strong>上不满足策略：KU/EKU/Profile/曲线不允许、
 * 算法不允许、证书过期/尚未生效、已吊销、证书链不可信、收方身份冲突等。
 * 此类失败<strong>不可重试</strong>（{@link #isRetryable()} 恒为 false，动作语义
 * {@link Action#DO_NOT_RETRY}）——重试不能改变证书固有属性。
 * <p>
 * <strong>不得</strong>把本异常包装为 {@link CertificateMaterialUnavailableException}
 * （后者表示材料源/依赖暂时不可用，可重试）。业务服务负责将其映射为自身错误码，但不得标为可重试。
 * <p>
 * 典型触发点：{@code CertificateEvidenceValidator.verifyKeyUsage()} 对 EC 收方缺少
 * {@code keyAgreement}、RSA 收方缺少 {@code keyEncipherment} 直接抛出本异常。
 */
public class CertificateEvidenceRejectedException extends CryptoException {

    /**
     * 策略拒绝原因（封闭集合）。
     */
    public enum Reason {
        /** 密钥用途（KU）不允许：EC 缺 keyAgreement / RSA 缺 keyEncipherment */
        KEY_USAGE_NOT_PERMITTED,
        /** 扩展密钥用途（EKU）不满足策略 */
        EXTENDED_KEY_USAGE_NOT_PERMITTED,
        /** Profile 不允许 */
        PROFILE_NOT_ALLOWED,
        /** 公钥算法不允许 */
        KEY_ALGORITHM_NOT_ALLOWED,
        /** 曲线不允许（EC 收方必须是 P-256） */
        CURVE_NOT_ALLOWED,
        /** 不支持的收方公钥类型（无法用于 ECDH/RSA-OAEP 封装） */
        UNSUPPORTED_RECIPIENT_KEY,
        /** 证书已过期 */
        CERTIFICATE_EXPIRED,
        /** 证书尚未生效 */
        CERTIFICATE_NOT_YET_VALID,
        /** 证书有效期区间非法 */
        CERTIFICATE_VALIDITY_INVALID,
        /** 证书已吊销 */
        CERTIFICATE_REVOKED,
        /** 证书链不可信 */
        CHAIN_NOT_TRUSTED
    }

    /**
     * 处理动作（首期仅 {@link #DO_NOT_RETRY}）。
     */
    public enum Action {
        /** 不得重试 */
        DO_NOT_RETRY
    }

    private final Reason rejectReason;
    private final Action action;

    public CertificateEvidenceRejectedException(Reason rejectReason, String message) {
        this(rejectReason, Action.DO_NOT_RETRY, message, null);
    }

    public CertificateEvidenceRejectedException(Reason rejectReason, String message, Throwable cause) {
        this(rejectReason, Action.DO_NOT_RETRY, message, cause);
    }

    public CertificateEvidenceRejectedException(Reason rejectReason, Action action, String message) {
        this(rejectReason, action, message, null);
    }

    public CertificateEvidenceRejectedException(Reason rejectReason, Action action, String message,
                                                Throwable cause) {
        super(CryptoException.Reason.CERTIFICATE_EVIDENCE_REJECTED, message, cause);
        this.rejectReason = rejectReason;
        this.action = action == null ? Action.DO_NOT_RETRY : action;
    }

    /**
     * 策略拒绝原因。
     */
    public Reason rejectReason() {
        return rejectReason;
    }

    /**
     * 处理动作语义。
     */
    public Action action() {
        return action;
    }

    /**
     * 证书策略拒绝恒不可重试。
     */
    @Override
    public boolean isRetryable() {
        return false;
    }
}
