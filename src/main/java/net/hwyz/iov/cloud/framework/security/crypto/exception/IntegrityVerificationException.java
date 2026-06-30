package net.hwyz.iov.cloud.framework.security.crypto.exception;

public class IntegrityVerificationException extends CryptoException {

    public IntegrityVerificationException(String message) {
        super(Reason.INTEGRITY_VERIFICATION_FAILED, message);
    }

    public IntegrityVerificationException(String message, Throwable cause) {
        super(Reason.INTEGRITY_VERIFICATION_FAILED, message, cause);
    }
}
