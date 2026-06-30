package net.hwyz.iov.cloud.framework.security.crypto.exception;

public class KeyRevokedException extends CryptoException {

    public KeyRevokedException(String message) {
        super(Reason.KEY_REVOKED, message);
    }

    public KeyRevokedException(String message, Throwable cause) {
        super(Reason.KEY_REVOKED, message, cause);
    }
}
