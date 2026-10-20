package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 统一 TBOX 设备证书 Profile 验证能力未装配异常（FW-SEC-DSN-CR-017 §10）。
 * <p>
 * 表示 TboxDeviceCertificateValidator / Profile 能力未装配（{@code crypto.keyprov.certificate-profile.enabled}
 * 未开启或 Bean 缺失）而调用方请求 Profile 验证时抛出——与「证书固有属性拒绝」不同，
 * 属独立 unavailable 分类。调用方应据此识别能力缺失而非证书问题。
 */
public class CertificateProfileVerificationUnavailableException extends CryptoException {

    public CertificateProfileVerificationUnavailableException(String message) {
        this(message, null);
    }

    public CertificateProfileVerificationUnavailableException(String message, Throwable cause) {
        super(CryptoException.Reason.CERTIFICATE_PROFILE_UNAVAILABLE, message, cause);
    }

    /**
     * 能力缺失在启动门禁/readiness 场景可重试（配置修正后恢复）；运行时使用按 fail-closed 处理。
     */
    @Override
    public boolean isRetryable() {
        return false;
    }
}
