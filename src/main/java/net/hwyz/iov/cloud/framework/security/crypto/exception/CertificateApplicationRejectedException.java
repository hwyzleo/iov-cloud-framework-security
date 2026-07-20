package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书申请被拒绝异常
 */
public class CertificateApplicationRejectedException extends CryptoException {

    public CertificateApplicationRejectedException(String message) {
        super(Reason.CERTIFICATE_APPLICATION_REJECTED, message);
    }

    public CertificateApplicationRejectedException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_APPLICATION_REJECTED, message, cause);
    }
}
