package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;

/**
 * 证书材料解析能力健康指标（FW-SEC-DSN-CR-012 §8）。
 * <p>
 * 表示「证书解析能力是否就绪」，不默认拖垮无关业务接口的全局 readiness；是否纳入 Health Group
 * 由消费方配置。
 * <ul>
 *   <li>未启用（一般不会注册本 Bean，防御性返回 UNKNOWN）；</li>
 *   <li>启用但缺信任锚 / require-good-status 与吊销能力冲突：NOT_READY；</li>
 *   <li>启用且配置合法：UP。</li>
 * </ul>
 */
public class CertificateResolutionHealthIndicator implements HealthIndicator {

    /**
     * 能力未就绪状态（区别于 DOWN：依赖未就绪但进程健康）
     */
    public static final Status NOT_READY = new Status("NOT_READY", "Certificate resolution capability not ready");

    private static final String CAPABILITY = "crypto.pki.certificate-resolution";

    private final CryptoProperties properties;
    private final boolean revocationEnabled;
    private final boolean resultStoreAvailable;
    private final boolean pkiClientAvailable;
    private final boolean domainDirectoryAvailable;

    public CertificateResolutionHealthIndicator(CryptoProperties properties, boolean revocationEnabled) {
        this(properties, revocationEnabled, true, true, true);
    }

    public CertificateResolutionHealthIndicator(CryptoProperties properties, boolean revocationEnabled,
                                                boolean resultStoreAvailable, boolean pkiClientAvailable,
                                                boolean domainDirectoryAvailable) {
        this.properties = properties;
        this.revocationEnabled = revocationEnabled;
        this.resultStoreAvailable = resultStoreAvailable;
        this.pkiClientAvailable = pkiClientAvailable;
        this.domainDirectoryAvailable = domainDirectoryAvailable;
    }

    @Override
    public Health health() {
        if (properties == null || properties.getPki() == null
                || !properties.getPki().getCertificateResolution().isEnabled()) {
            return Health.unknown()
                    .withDetail("capability", CAPABILITY)
                    .withDetail("enabled", false)
                    .build();
        }
        Health.Builder builder;
        String reason = CertificateResolutionValidator.inspect(properties, revocationEnabled);
        if (reason != null) {
            builder = Health.status(NOT_READY).withDetail("reason", reason);
        } else {
            builder = Health.up();
        }
        return builder
                .withDetail("capability", CAPABILITY)
                .withDetail("resultStoreAvailable", resultStoreAvailable)
                .withDetail("pkiClientAvailable", pkiClientAvailable)
                .withDetail("domainDirectoryAvailable", domainDirectoryAvailable)
                .build();
    }
}
