package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书未就绪异常
 */
public class CertificateNotReadyException extends CryptoException {

    public CertificateNotReadyException(String message) {
        super(Reason.CERTIFICATE_NOT_READY, message);
    }

    public CertificateNotReadyException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_NOT_READY, message, cause);
    }
}
