package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书引用不唯一异常（FW-SEC-DSN-CR-012 §6）。
 * <p>
 * 同一 serial/主体命中多个不同 locator，或同一 serial 对应多个不同指纹时抛出；
 * 领域目录权威不被 framework 拥有，故不做猜测或按序取首个。
 */
public class CertificateReferenceAmbiguousException extends CryptoException {

    public CertificateReferenceAmbiguousException(String message) {
        super(Reason.CERTIFICATE_REFERENCE_AMBIGUOUS, message);
    }

    public CertificateReferenceAmbiguousException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_REFERENCE_AMBIGUOUS, message, cause);
    }
}
