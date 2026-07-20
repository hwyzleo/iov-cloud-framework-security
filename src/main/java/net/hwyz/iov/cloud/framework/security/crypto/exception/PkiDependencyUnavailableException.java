package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * PKI 依赖不可用异常
 */
public class PkiDependencyUnavailableException extends CryptoException {

    public PkiDependencyUnavailableException(String message) {
        super(Reason.PKI_DEPENDENCY_UNAVAILABLE, message);
    }

    public PkiDependencyUnavailableException(String message, Throwable cause) {
        super(Reason.PKI_DEPENDENCY_UNAVAILABLE, message, cause);
    }
}
