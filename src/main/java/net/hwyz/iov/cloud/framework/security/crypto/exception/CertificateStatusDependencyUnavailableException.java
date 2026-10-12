package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书状态查询依赖不可用异常（FW-SEC-DSN-CR-010 §7）
 * <p>
 * 对应 DNS 失败、连接拒绝/重置、5xx/429 等「依赖侧不可用」的结果。
 * 消费方必须 fail-closed，禁止将其映射为证书有效。
 */
public class CertificateStatusDependencyUnavailableException extends CryptoException {

    public CertificateStatusDependencyUnavailableException(String message) {
        super(Reason.CERTIFICATE_STATUS_DEPENDENCY_UNAVAILABLE, message);
    }

    public CertificateStatusDependencyUnavailableException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_STATUS_DEPENDENCY_UNAVAILABLE, message, cause);
    }
}
