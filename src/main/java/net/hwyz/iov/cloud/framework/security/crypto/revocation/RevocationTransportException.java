package net.hwyz.iov.cloud.framework.security.crypto.revocation;

/**
 * 吊销查询传输层异常（FW-SEC-DSN-CR-010 §6/§7）
 * <p>
 * 只表达「传输阶段与是否可安全重试」，由协议检查器映射为 framework 类型化异常，
 * 避免业务层直接依赖底层 IO 异常类型。禁止在消息中携带 token、证书或凭据。
 */
public class RevocationTransportException extends RuntimeException {

    /**
     * 传输失败阶段
     */
    public enum Phase {
        /**
         * DNS 解析失败（不可重试）
         */
        DNS,
        /**
         * 连接建立失败/超时（请求尚未发出，可重试）
         */
        CONNECT,
        /**
         * TLS 握手/校验失败（不可重试，安全事件）
         */
        TLS,
        /**
         * 请求已发出但读超时（结果未知，不可重试）
         */
        READ_TIMEOUT,
        /**
         * 连接重置/中断（请求可能已发出，按设计可重试一次）
         */
        RESET,
        /**
         * 收到重定向但重定向被禁用/未解析（协议错误，不可重试）
         */
        REDIRECT,
        /**
         * 线程被中断（结果未知，不可重试）
         */
        INTERRUPTED,
        /**
         * 受管线程池拒绝（依赖侧不可用，不可重试）
         */
        EXECUTOR_REJECTED
    }

    private final Phase phase;
    private final int statusCode;

    public RevocationTransportException(Phase phase, String message, Throwable cause) {
        this(phase, 0, message, cause);
    }

    public RevocationTransportException(Phase phase, int statusCode, String message, Throwable cause) {
        super(message, cause);
        this.phase = phase;
        this.statusCode = statusCode;
    }

    public Phase getPhase() {
        return phase;
    }

    public int getStatusCode() {
        return statusCode;
    }

    /**
     * 是否属于设计允许的安全重试（仅连接建立失败与连接重置；DNS/TLS/读超时/中断/拒绝均不可重试）。
     */
    public boolean retryable() {
        return phase == Phase.CONNECT || phase == Phase.RESET;
    }
}
