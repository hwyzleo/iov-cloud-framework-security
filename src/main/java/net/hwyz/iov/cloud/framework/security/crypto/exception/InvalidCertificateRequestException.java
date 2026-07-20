package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 无效证书请求异常
 */
public class InvalidCertificateRequestException extends CryptoException {

    public InvalidCertificateRequestException(String message) {
        super(Reason.INVALID_CERTIFICATE_REQUEST, message);
    }

    public InvalidCertificateRequestException(String message, Throwable cause) {
        super(Reason.INVALID_CERTIFICATE_REQUEST, message, cause);
    }
}
