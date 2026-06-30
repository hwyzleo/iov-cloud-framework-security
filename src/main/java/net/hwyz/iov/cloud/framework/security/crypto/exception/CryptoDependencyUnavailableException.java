package net.hwyz.iov.cloud.framework.security.crypto.exception;

public class CryptoDependencyUnavailableException extends CryptoException {

    public CryptoDependencyUnavailableException(String message) {
        super(Reason.DEPENDENCY_UNAVAILABLE, message);
    }

    public CryptoDependencyUnavailableException(String message, Throwable cause) {
        super(Reason.DEPENDENCY_UNAVAILABLE, message, cause);
    }
}
