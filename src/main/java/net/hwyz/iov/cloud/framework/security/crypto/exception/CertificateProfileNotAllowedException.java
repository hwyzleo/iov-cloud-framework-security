package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书配置文件不允许异常
 */
public class CertificateProfileNotAllowedException extends CryptoException {

    public CertificateProfileNotAllowedException(String message) {
        super(Reason.CERTIFICATE_PROFILE_NOT_ALLOWED, message);
    }

    public CertificateProfileNotAllowedException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_PROFILE_NOT_ALLOWED, message, cause);
    }
}
