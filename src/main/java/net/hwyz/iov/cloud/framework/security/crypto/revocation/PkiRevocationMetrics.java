package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * PKI 证书状态查询指标（FW-SEC-DSN-CR-010 §9）
 * <p>
 * 指标：
 * <ul>
 *   <li>{@code framework.pki.certificate.status}（provider, source, outcome）</li>
 *   <li>{@code framework.pki.certificate.status.latency}（source）</li>
 *   <li>{@code framework.pki.certificate.status.retry}（cause）</li>
 *   <li>{@code framework.pki.certificate.status.validation.failure}（category）</li>
 * </ul>
 * 标签仅使用固定低基数枚举；禁止 serial、fingerprint、subject、uid、endpoint、token 作为 label。
 */
@Component
public class PkiRevocationMetrics implements MeterBinder {

    private final MeterRegistry meterRegistry;

    public PkiRevocationMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        // 预注册基础计数器，便于无流量时 Exporter 也能暴露 series
        registry.counter("framework.pki.certificate.status", "provider", "unknown", "source", "none",
                "outcome", "unknown");
        registry.counter("framework.pki.certificate.status.retry", "cause", "none");
        registry.counter("framework.pki.certificate.status.validation.failure", "category", "none");
    }

    /**
     * 记录一次状态查询结果。
     *
     * @param provider 签发 Provider（step-ca/legacy-rest/unknown）
     * @param source   来源（ocsp/crl/unknown）
     * @param outcome  结果（good/revoked/unknown/disabled/error）
     */
    public void recordStatus(String provider, String source, String outcome) {
        meterRegistry.counter("framework.pki.certificate.status",
                "provider", normalizeProvider(provider),
                "source", normalizeSource(source),
                "outcome", normalizeOutcome(outcome)).increment();
    }

    /**
     * 记录查询时延。
     *
     * @param source 来源
     * @param nanos  耗时（纳秒）
     */
    public void recordLatency(String source, long nanos) {
        meterRegistry.timer("framework.pki.certificate.status.latency",
                "source", normalizeSource(source)).record(nanos, TimeUnit.NANOSECONDS);
    }

    /**
     * 记录一次重试及其原因。
     *
     * @param cause 固定枚举原因（connect/reset/http-502/http-503/http-504/unknown）
     */
    public void recordRetry(String cause) {
        meterRegistry.counter("framework.pki.certificate.status.retry",
                "cause", normalizeRetryCause(cause)).increment();
    }

    /**
     * 记录一次校验失败类别。
     *
     * @param category 固定枚举（tls/signature/issuer/serial/stale/fingerprint/parse/nonce/dns/timeout）
     */
    public void recordValidationFailure(String category) {
        meterRegistry.counter("framework.pki.certificate.status.validation.failure",
                "category", normalizeValidationCategory(category)).increment();
    }

    private static String normalizeProvider(String provider) {
        if (provider == null) {
            return "unknown";
        }
        return switch (provider.trim().toLowerCase()) {
            case "step-ca" -> "step-ca";
            case "legacy-rest", "legacy" -> "legacy-rest";
            default -> "unknown";
        };
    }

    private static String normalizeSource(String source) {
        if (source == null) {
            return "unknown";
        }
        return switch (source.trim().toLowerCase()) {
            case "ocsp" -> "ocsp";
            case "crl" -> "crl";
            default -> "unknown";
        };
    }

    private static String normalizeOutcome(String outcome) {
        if (outcome == null) {
            return "unknown";
        }
        return switch (outcome.trim().toLowerCase()) {
            case "good" -> "good";
            case "revoked" -> "revoked";
            case "unknown" -> "unknown";
            case "disabled" -> "disabled";
            case "error", "failure", "failed" -> "error";
            default -> "unknown";
        };
    }

    private static String normalizeRetryCause(String cause) {
        if (cause == null) {
            return "unknown";
        }
        String normalized = cause.trim().toLowerCase();
        return switch (normalized) {
            case "connect" -> "connect";
            case "reset" -> "reset";
            case "http-502" -> "http-502";
            case "http-503" -> "http-503";
            case "http-504" -> "http-504";
            default -> "unknown";
        };
    }

    private static String normalizeValidationCategory(String category) {
        if (category == null) {
            return "unknown";
        }
        return switch (category.trim().toLowerCase()) {
            case "tls" -> "tls";
            case "signature" -> "signature";
            case "issuer" -> "issuer";
            case "serial" -> "serial";
            case "stale" -> "stale";
            case "fingerprint" -> "fingerprint";
            case "parse" -> "parse";
            case "nonce" -> "nonce";
            case "dns" -> "dns";
            case "timeout" -> "timeout";
            default -> "unknown";
        };
    }
}
