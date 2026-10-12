package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;

/**
 * PKI 证书状态能力健康指标（FW-SEC-DSN-CR-010 §3.3/§5）
 * <p>
 * 表示「证书状态/吊销查询能力是否就绪」，不默认拖垮无关业务接口的全局 readiness；
 * 是否纳入 Health Group 由消费方配置。
 * <ul>
 *   <li>配置合法且已启用：UP；</li>
 *   <li>启用但配置非法 / 缺 issuer、信任锚、URL 来源或预算关系非法：NOT_READY；</li>
 *   <li>能力未启用（一般不会注册本 Bean，防御性返回 UNKNOWN）。</li>
 * </ul>
 */
public class PkiRevocationHealthIndicator implements HealthIndicator {

    /**
     * 能力未就绪状态（区别于 DOWN：依赖未就绪但进程健康）
     */
    public static final Status NOT_READY = new Status("NOT_READY", "PKI revocation capability not ready");

    private static final String CAPABILITY = "crypto.pki.revocation";

    private final PkiRevocationProperties properties;
    private final String notReadyReason;

    public PkiRevocationHealthIndicator(PkiRevocationProperties properties, String notReadyReason) {
        this.properties = properties;
        this.notReadyReason = notReadyReason;
    }

    @Override
    public Health health() {
        if (!properties.isEnabled()) {
            return Health.unknown()
                    .withDetail("capability", CAPABILITY)
                    .withDetail("enabled", false)
                    .build();
        }
        if (notReadyReason != null && !notReadyReason.isBlank()) {
            return Health.status(NOT_READY)
                    .withDetail("capability", CAPABILITY)
                    .withDetail("reason", notReadyReason)
                    .build();
        }
        return Health.up()
                .withDetail("capability", CAPABILITY)
                .withDetail("mode", properties.normalizedMode())
                .build();
    }
}
