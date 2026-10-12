package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusProtocolException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusTrustValidationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * 默认证书状态检查器（FW-SEC-DSN-CR-010 §3.2/§6/§8）
 * <p>
 * 按 {@code crypto.pki.revocation.mode} 编排 OCSP/CRL：
 * <ul>
 *   <li>{@code ocsp}：仅 OCSP；</li>
 *   <li>{@code crl}：仅 CRL；</li>
 *   <li>{@code ocsp-then-crl}：OCSP 优先；仅在 OCSP 端点不可用、依赖/结果未知或返回 UNKNOWN 且剩余预算充足时进入 CRL；
 *       OCSP 明确 REVOKED 不再查询 CRL，绝不以任一来源 GOOD 覆盖另一来源 REVOKED。</li>
 * </ul>
 * 所有协议尝试与重试共享 {@code total-timeout}。
 */
public class DefaultCertificateStatusChecker implements CertificateStatusChecker {

    private static final Logger log = LoggerFactory.getLogger(DefaultCertificateStatusChecker.class);

    private final CertificateDirectoryResolver resolver;
    private final PkiRevocationProperties properties;
    private final RevocationProtocolChecker ocspChecker;
    private final RevocationProtocolChecker crlChecker;
    private final PkiRevocationMetrics metrics;

    public DefaultCertificateStatusChecker(CertificateDirectoryResolver resolver,
                                           PkiRevocationProperties properties,
                                           RevocationProtocolChecker ocspChecker,
                                           RevocationProtocolChecker crlChecker,
                                           PkiRevocationMetrics metrics) {
        this.resolver = Objects.requireNonNull(resolver, "resolver must not be null");
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.ocspChecker = Objects.requireNonNull(ocspChecker, "ocspChecker must not be null");
        this.crlChecker = Objects.requireNonNull(crlChecker, "crlChecker must not be null");
        this.metrics = Objects.requireNonNull(metrics, "metrics must not be null");
    }

    @Override
    public PkiClient.CertificateStatusResult check(PkiClient.CertificateStatusQuery query) {
        Objects.requireNonNull(query, "query must not be null");
        if (!properties.isEnabled()) {
            throw new CertificateStatusConfigurationException(
                    "crypto.pki.revocation.enabled=false; certificate status query is disabled");
        }

        long startedNanos = System.nanoTime();
        Instant now = Instant.now();
        Instant deadline = now.plus(properties.getTotalTimeout() != null
                ? properties.getTotalTimeout() : Duration.ofSeconds(1));
        Instant decisionAt = query.decisionAt() != null ? query.decisionAt() : now;

        CertificateStatusContext context = null;
        try {
            context = resolver.resolve(query);
            PkiClient.CertificateStatusResult result = switch (properties.normalizedMode()) {
                case "ocsp" -> require(ocspChecker.check(context, decisionAt, deadline));
                case "crl" -> require(crlChecker.check(context, decisionAt, deadline));
                case "ocsp-then-crl" -> ocspThenCrl(context, decisionAt, deadline);
                default -> throw new CertificateStatusConfigurationException(
                        "Unsupported crypto.pki.revocation.mode: " + properties.getMode()
                                + " (expect ocsp | crl | ocsp-then-crl)");
            };
            metrics.recordStatus(context.provider(), normalizeSource(result.source()), outcomeOf(result));
            metrics.recordLatency(normalizeSource(result.source()), System.nanoTime() - startedNanos);
            return result;
        } catch (CryptoException e) {
            metrics.recordStatus(context != null ? context.provider() : "unknown", "unknown", "error");
            metrics.recordLatency("unknown", System.nanoTime() - startedNanos);
            recordFailureCategory(e);
            throw e;
        } catch (RuntimeException e) {
            metrics.recordStatus(context != null ? context.provider() : "unknown", "unknown", "error");
            metrics.recordLatency("unknown", System.nanoTime() - startedNanos);
            throw e;
        }
    }

    private PkiClient.CertificateStatusResult ocspThenCrl(CertificateStatusContext context,
                                                         Instant decisionAt,
                                                         Instant deadline) {
        if (context.ocspUri() == null) {
            if (context.crlUri() == null) {
                throw new CertificateStatusConfigurationException(
                        "Neither OCSP responder nor CRL distribution point is available; "
                                + "PKI revocation capability is NOT_READY (FW-SEC-DSN-CR-010 §3.3)");
            }
            return require(crlChecker.check(context, decisionAt, deadline));
        }

        PkiClient.CertificateStatusResult ocspResult;
        try {
            ocspResult = require(ocspChecker.check(context, decisionAt, deadline));
        } catch (CertificateStatusDependencyUnavailableException | CertificateStatusOutcomeUnknownException e) {
            // 仅对「端点不可用/结果未知」允许受控后备；TLS/协议/配置失败属于安全事件，立即 fail-closed
            if (!crlAvailable(context, deadline)) {
                throw e;
            }
            log.warn("OCSP 不可用，进入 CRL 受控后备: phase={}", e.getReason());
            return require(crlChecker.check(context, decisionAt, deadline));
        }

        if (ocspResult.revocationState() == PkiClient.RevocationState.GOOD
                || ocspResult.revocationState() == PkiClient.RevocationState.REVOKED) {
            // 明确结论（含 REVOKED）不再查询 CRL：禁止任一来源 GOOD 覆盖另一来源 REVOKED
            return ocspResult;
        }

        // OCSP UNKNOWN：无可用判定结论，若 CRL 可用则受控后备
        if (!crlAvailable(context, deadline)) {
            return ocspResult;
        }
        log.warn("OCSP 返回 UNKNOWN，进入 CRL 受控后备");
        return require(crlChecker.check(context, decisionAt, deadline));
    }

    private boolean crlAvailable(CertificateStatusContext context, Instant deadline) {
        if (context.crlUri() == null) {
            return false;
        }
        Duration remaining = Duration.between(Instant.now(), deadline);
        Duration minBudget = properties.getMinRetryBudget() != null
                ? properties.getMinRetryBudget() : Duration.ofMillis(300);
        return remaining.compareTo(minBudget) >= 0;
    }

    private static PkiClient.CertificateStatusResult require(PkiClient.CertificateStatusResult result) {
        if (result == null) {
            throw new CertificateStatusProtocolException("Certificate status checker returned null result");
        }
        return result;
    }

    private static String outcomeOf(PkiClient.CertificateStatusResult result) {
        return result.revocationState().name().toLowerCase();
    }

    private static String normalizeSource(PkiClient.RevocationSource source) {
        return source.name().toLowerCase();
    }

    private void recordFailureCategory(CryptoException e) {
        if (e instanceof CertificateStatusTrustValidationException) {
            metrics.recordValidationFailure("tls");
        } else if (e instanceof CertificateStatusProtocolException) {
            metrics.recordValidationFailure("parse");
        }
    }

    /**
     * 启动期能力就绪校验（非抛异常）：非法配置令 revocation Health NOT_READY。
     */
    public static void validateConfiguration(PkiRevocationProperties properties) {
        String mode = properties.normalizedMode();
        if (!mode.equals("ocsp") && !mode.equals("crl") && !mode.equals("ocsp-then-crl")) {
            throw new CertificateStatusConfigurationException("Unsupported crypto.pki.revocation.mode: " + mode);
        }
        String noncePolicy = properties.getOcsp().normalizedNoncePolicy();
        if (!noncePolicy.equals("required") && !noncePolicy.equals("optional")
                && !noncePolicy.equals("disabled")) {
            throw new CertificateStatusConfigurationException(
                    "Unsupported crypto.pki.revocation.ocsp.nonce-policy: " + noncePolicy);
        }
        String authMode = properties.getAuth().normalizedMode();
        if (!authMode.equals("none") && !authMode.equals("bearer") && !authMode.equals("mtls")) {
            throw new CertificateStatusConfigurationException(
                    "Unsupported crypto.pki.revocation.auth.mode: " + authMode);
        }
        Duration total = properties.getTotalTimeout();
        if (total == null || total.isNegative() || total.isZero()) {
            throw new CertificateStatusConfigurationException(
                    "crypto.pki.revocation.total-timeout must be positive");
        }
        Duration skew = properties.getClockSkew();
        if (skew == null || skew.isNegative()) {
            throw new CertificateStatusConfigurationException(
                    "crypto.pki.revocation.clock-skew must not be negative");
        }
    }
}
