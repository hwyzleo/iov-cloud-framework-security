package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 统一 TBOX 设备证书 Profile 策略拒绝异常（FW-SEC-DSN-CR-017 §10）。
 * <p>
 * 表示证书在统一 Profile 的<strong>确定性固有属性</strong>上不满足策略（CA=false、P-256、
 * 双 KU、clientAuth、关键扩展、身份绑定、绑定一致性等）。此类失败<strong>不可重试</strong>
 * （{@link #isRetryable()} 恒为 false）——重试不能改变证书固有属性。
 * <p>
 * 携带稳定 {@link CertificateProfileRejectReason} 供 VMD 等消费方映射；
 * <strong>不得</strong>依赖异常正文解析。
 * <p>
 * <strong>不得</strong>包装为 {@link CertificateMaterialUnavailableException}（后者表示材料源/
 * 依赖暂时不可用，可重试）。状态类拒绝（过期/吊销/链不可信）保持由
 * {@link CertificateEvidenceRejectedException} 承载。
 */
public class CertificateProfileRejectedException extends CryptoException {

    private final CertificateProfileRejectReason rejectReason;

    public CertificateProfileRejectedException(CertificateProfileRejectReason rejectReason, String message) {
        this(rejectReason, message, null);
    }

    public CertificateProfileRejectedException(CertificateProfileRejectReason rejectReason, String message,
                                               Throwable cause) {
        super(CryptoException.Reason.CERTIFICATE_PROFILE_REJECTED, message, cause);
        if (rejectReason == null) {
            throw new IllegalArgumentException("rejectReason must not be null");
        }
        this.rejectReason = rejectReason;
    }

    /**
     * 稳定策略拒绝原因。
     */
    public CertificateProfileRejectReason rejectReason() {
        return rejectReason;
    }

    /**
     * Profile 策略拒绝恒不可重试。
     */
    @Override
    public boolean isRetryable() {
        return false;
    }
}
