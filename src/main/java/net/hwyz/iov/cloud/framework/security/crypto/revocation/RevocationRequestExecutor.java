package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusTrustValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

/**
 * 受预算约束的吊销查询请求执行器（FW-SEC-DSN-CR-010 §6）
 * <p>
 * 统一处理：
 * <ul>
 *   <li>所有协议尝试与重试共享单次 total budget；</li>
 *   <li>仅对「请求发出前连接失败、连接 reset、502/503/504 且剩余预算不少于 min-retry-budget」重试；</li>
 *   <li>DNS、TLS、4xx、协议校验失败、UNKNOWN 不重试；读超时→outcome unknown 且不重试；</li>
 *   <li>将传输阶段映射为 framework 类型化异常并保留 cause。</li>
 * </ul>
 */
class RevocationRequestExecutor {

    private static final Logger log = LoggerFactory.getLogger(RevocationRequestExecutor.class);

    private final RevocationHttpTransport transport;
    private final PkiRevocationProperties properties;
    private final PkiRevocationMetrics metrics;
    private final Duration defaultReadTimeout;

    RevocationRequestExecutor(RevocationHttpTransport transport,
                              PkiRevocationProperties properties,
                              PkiRevocationMetrics metrics,
                              Duration defaultReadTimeout) {
        this.transport = transport;
        this.properties = properties;
        this.metrics = metrics;
        this.defaultReadTimeout = defaultReadTimeout != null ? defaultReadTimeout : Duration.ofMillis(500);
    }

    /**
     * 执行一次带重试的协议请求。
     *
     * @param call     接收「本次可用 read timeout」的请求函数
     * @param deadline 总预算截止时刻
     */
    RevocationHttpTransport.Response execute(Function<Duration, RevocationHttpTransport.Response> call,
                                             Instant deadline) {
        int maxAttempts = Math.max(0, properties.getRetry().getMaxAttempts());
        int attempt = 0;
        while (true) {
            Duration timeout = effectiveTimeout(deadline);
            try {
                RevocationHttpTransport.Response response = call.apply(timeout);
                if (isRetryableStatus(response.statusCode()) && canRetry(attempt, maxAttempts, deadline)) {
                    String cause = "http-" + response.statusCode();
                    metrics.recordRetry(cause);
                    log.warn("吊销查询返回可重试状态，准备重试 ({}/{}): status={}",
                            attempt + 1, maxAttempts, response.statusCode());
                    sleep(backoff(attempt), deadline);
                    attempt++;
                    continue;
                }
                return response;
            } catch (RevocationTransportException e) {
                if (e.retryable() && canRetry(attempt, maxAttempts, deadline)) {
                    String cause = e.getPhase() == RevocationTransportException.Phase.CONNECT
                            ? "connect" : "reset";
                    metrics.recordRetry(cause);
                    log.warn("吊销查询传输失败，准备重试 ({}/{}): phase={}",
                            attempt + 1, maxAttempts, e.getPhase());
                    sleep(backoff(attempt), deadline);
                    attempt++;
                    continue;
                }
                throw map(e);
            }
        }
    }

    /**
     * 逐次请求的 read timeout：不超过配置值，且不超过剩余预算。
     */
    Duration effectiveTimeout(Instant deadline) {
        Duration remaining = Duration.between(Instant.now(), deadline);
        Duration timeout = defaultReadTimeout;
        if (remaining.compareTo(timeout) < 0) {
            timeout = remaining;
        }
        if (timeout.isNegative() || timeout.isZero()) {
            timeout = Duration.ofMillis(50);
        }
        return timeout;
    }

    /**
     * 传输阶段 → framework 类型化异常（保留 cause）。
     */
    private RuntimeException map(RevocationTransportException e) {
        metrics.recordValidationFailure(categoryFor(e));
        return switch (e.getPhase()) {
            case DNS -> new CertificateStatusDependencyUnavailableException(
                    "Revocation endpoint DNS resolution failed", e);
            case CONNECT -> new CertificateStatusDependencyUnavailableException(
                    "Revocation endpoint connection failed", e);
            case TLS -> new CertificateStatusTrustValidationException(
                    "Revocation endpoint TLS validation failed", e);
            case READ_TIMEOUT, INTERRUPTED -> new CertificateStatusOutcomeUnknownException(
                    "Revocation request outcome unknown (no determinate response)", e);
            case REDIRECT -> new net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusProtocolException(
                    "Revocation endpoint returned an unexpected redirect", e);
            case RESET -> new CertificateStatusDependencyUnavailableException(
                    "Revocation connection failed after send", e);
            case EXECUTOR_REJECTED -> new CertificateStatusDependencyUnavailableException(
                    "Revocation transport thread pool rejected the request", e);
        };
    }

    private static String categoryFor(RevocationTransportException e) {
        return switch (e.getPhase()) {
            case DNS -> "dns";
            case TLS -> "tls";
            case READ_TIMEOUT, INTERRUPTED -> "timeout";
            case REDIRECT -> "parse";
            default -> "connect";
        };
    }

    private boolean canRetry(int attempt, int maxAttempts, Instant deadline) {
        if (attempt >= maxAttempts) {
            return false;
        }
        Duration remaining = Duration.between(Instant.now(), deadline);
        return remaining.compareTo(properties.getMinRetryBudget()) >= 0;
    }

    private Duration backoff(int attempt) {
        long base = properties.getRetry().getBaseBackoff().toMillis();
        return Duration.ofMillis(Math.min(base * (1L << attempt), 5000));
    }

    private void sleep(Duration duration, Instant deadline) {
        Duration remaining = Duration.between(Instant.now(), deadline);
        long millis = Math.min(duration.toMillis(), Math.max(remaining.toMillis(), 1));
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CertificateStatusOutcomeUnknownException(
                    "Revocation retry interrupted; outcome unknown", e);
        }
    }

    private static boolean isRetryableStatus(int statusCode) {
        return statusCode == 502 || statusCode == 503 || statusCode == 504;
    }
}
