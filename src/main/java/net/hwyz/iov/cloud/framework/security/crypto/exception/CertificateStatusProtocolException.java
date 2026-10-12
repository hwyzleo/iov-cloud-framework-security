package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书状态查询协议错误异常（FW-SEC-DSN-CR-010 §7）
 * <p>
 * 对应响应解析失败、serial/fingerprint 不一致、issuer 不符、OCSP/CRL 签名非法、
 * OCSP 响应过期（stale）等「拿到响应但不可信/不可用」的结果。禁止重试。
 */
public class CertificateStatusProtocolException extends CryptoException {

    public CertificateStatusProtocolException(String message) {
        super(Reason.CERTIFICATE_STATUS_PROTOCOL_ERROR, message);
    }

    public CertificateStatusProtocolException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_STATUS_PROTOCOL_ERROR, message, cause);
    }
}
