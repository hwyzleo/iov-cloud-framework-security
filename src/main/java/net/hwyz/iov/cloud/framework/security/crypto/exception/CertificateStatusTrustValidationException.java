package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书状态查询信任校验失败异常（FW-SEC-DSN-CR-010 §7）
 * <p>
 * 对应 TLS 握手/证书链/SAN/主机名校验失败，或 OCSP/CRL 响应签名、issuer 授权校验失败。
 * 属于安全事件，禁止重试与降级为 GOOD。
 */
public class CertificateStatusTrustValidationException extends CryptoException {

    public CertificateStatusTrustValidationException(String message) {
        super(Reason.CERTIFICATE_STATUS_TRUST_VALIDATION_FAILED, message);
    }

    public CertificateStatusTrustValidationException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_STATUS_TRUST_VALIDATION_FAILED, message, cause);
    }
}
