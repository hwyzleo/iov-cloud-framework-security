package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 多来源证书证据不一致异常（FW-SEC-DSN-CR-012 §6）。
 * <p>
 * inline DER、requestId/result store、Provider serial query 与领域目录返回的
 * serial/指纹/公钥相互矛盾时抛出；绝不按 Bean 顺序或来源优先级静默择一。
 */
public class CertificateEvidenceMismatchException extends CryptoException {

    public CertificateEvidenceMismatchException(String message) {
        super(Reason.CERTIFICATE_EVIDENCE_MISMATCH, message);
    }

    public CertificateEvidenceMismatchException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_EVIDENCE_MISMATCH, message, cause);
    }
}
