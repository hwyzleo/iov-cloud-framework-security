package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyProviderRouter;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;

/**
 * Transit 派生能力健康指标（FW-SEC-DSN-CR-019 §10）。
 * <p>
 * 未启用 local-wrap（或 legacy provider）时报告 DISABLED；启用时按
 * {@link TransitDerivedKeyReadiness} 聚合上报 NOT_READY/UP。仅供运维门禁使用；
 * DOWN/NOT_READY 时<strong>不得</strong>向 VMD 声明完整 DERIVED_ROOT capability。
 */
public class TransitDerivedKeyHealthIndicator implements HealthIndicator {

    public static final Status DISABLED =
            new Status("DISABLED", "Transit derived key provider disabled");
    public static final Status NOT_READY =
            new Status("NOT_READY", "Transit derived key capability not ready");

    private final CryptoProperties properties;
    private final TransitDerivedKeyReadiness readiness;

    public TransitDerivedKeyHealthIndicator(CryptoProperties properties,
                                            TransitDerivedKeyReadiness readiness) {
        this.properties = properties;
        this.readiness = readiness;
    }

    @Override
    public Health health() {
        if (properties == null || properties.getProvisioning() == null
                || properties.getProvisioning().getDerivedKey() == null
                || !DerivedKeyProviderRouter.LOCAL_WRAP_PROVIDER.equals(
                        properties.getProvisioning().getDerivedKey().getProvider())) {
            return Health.status(DISABLED)
                    .withDetail("capability", "crypto.provisioning.derived-key")
                    .withDetail("provider", properties == null || properties.getProvisioning() == null
                            || properties.getProvisioning().getDerivedKey() == null
                            ? "unset" : properties.getProvisioning().getDerivedKey().getProvider())
                    .withDetail("enabled", false)
                    .build();
        }
        if (readiness == null) {
            return Health.status(NOT_READY)
                    .withDetail("capability", "crypto.provisioning.derived-key")
                    .withDetail("enabled", true)
                    .withDetail("reason", "transit derived key readiness is not wired")
                    .build();
        }
        String reason = readiness.notReadyReason();
        if (reason == null) {
            return Health.up()
                    .withDetail("capability", "crypto.provisioning.derived-key")
                    .withDetail("enabled", true)
                    .withDetail("provider", DerivedKeyProviderRouter.LOCAL_WRAP_PROVIDER)
                    .build();
        }
        return Health.status(NOT_READY)
                .withDetail("capability", "crypto.provisioning.derived-key")
                .withDetail("enabled", true)
                .withDetail("provider", DerivedKeyProviderRouter.LOCAL_WRAP_PROVIDER)
                .withDetail("reason", reason)
                .build();
    }
}
