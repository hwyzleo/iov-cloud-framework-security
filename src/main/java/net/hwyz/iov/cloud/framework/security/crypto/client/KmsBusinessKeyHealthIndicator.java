package net.hwyz.iov.cloud.framework.security.crypto.client;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

/**
 * 业务密钥 Provider readiness 健康指示（FW-SEC-DSN-CR-011 §8.3）。
 * <p>
 * capability 未 READY 时报告 DOWN，供 VMD keyprov readiness 与运维门禁使用；
 * 其他 VMD 能力不受影响（本指示器仅代表业务密钥 provider 分支）。
 */
public class KmsBusinessKeyHealthIndicator implements HealthIndicator {

    private final KmsBusinessKeyProviderReadiness readiness;

    public KmsBusinessKeyHealthIndicator(KmsBusinessKeyProviderReadiness readiness) {
        this.readiness = readiness;
    }

    @Override
    public Health health() {
        boolean ready = readiness.probe();
        KmsProviderCapabilities capabilities = readiness.getCapabilities();
        if (ready) {
            return Health.up()
                    .withDetail("provider", capabilities.provider())
                    .withDetail("apiVersion", capabilities.apiVersion())
                    .withDetail("mount", capabilities.mount())
                    .build();
        }
        return Health.down()
                .withDetail("reason", readiness.getReason())
                .withDetail("provider", capabilities.provider())
                .withDetail("mount", capabilities.mount())
                .build();
    }
}
