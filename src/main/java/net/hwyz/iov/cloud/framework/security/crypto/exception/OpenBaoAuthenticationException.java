package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * OpenBao 认证不可用/失败（FW-SEC-DSN-CR-019 §5.2）。
 * <p>
 * 中立认证组件失败统一抛此异常；由调用方（如 Transit 客户端）按自身语义映射为稳定 reason。
 * 消息不得包含 Token、RoleID/SecretID。
 */
public class OpenBaoAuthenticationException extends CryptoException {

    public OpenBaoAuthenticationException(String message) {
        super(CryptoException.Reason.DEPENDENCY_UNAVAILABLE, message);
    }

    public OpenBaoAuthenticationException(String message, Throwable cause) {
        super(CryptoException.Reason.DEPENDENCY_UNAVAILABLE, message, cause);
    }
}
