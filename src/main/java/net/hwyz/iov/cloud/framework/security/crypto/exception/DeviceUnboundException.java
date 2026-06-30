package net.hwyz.iov.cloud.framework.security.crypto.exception;

public class DeviceUnboundException extends CryptoException {

    public DeviceUnboundException(String message) {
        super(Reason.DEVICE_UNBOUND, message);
    }

    public DeviceUnboundException(String message, Throwable cause) {
        super(Reason.DEVICE_UNBOUND, message, cause);
    }
}
