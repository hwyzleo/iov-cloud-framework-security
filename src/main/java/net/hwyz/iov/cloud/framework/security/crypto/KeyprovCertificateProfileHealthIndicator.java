package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;

/**
 * 统一 TBOX 设备证书 Profile / 完整 Keyprov 能力健康指标（FW-SEC-DSN-CR-017 §9）。
 * <p>
 * 报告三个层面：Profile 能力（{@code KEYPROV_CERTIFICATE_READY}）与完整 ECDH-ES v1 聚合
 * （{@code KEYPROV_ECDH_ES_V1_READY}）。是否纳入 Health Group 由消费方配置。
 * <ul>
 *   <li>未启用（{@code crypto.keyprov.certificate-profile.enabled=false}）：{@link #DISABLED}，不声明 capability；</li>
 *   <li>启用但自检/吊销/信任锚/解析配置未就绪：{@link #NOT_READY}；</li>
 *   <li>启用且就绪：UP（含完整聚合状态明细）。</li>
 * </ul>
 * 仅供运维门禁使用；DOWN/NOT_READY 时<strong>不得</strong>向 VMD 声明完整
 * {@code KEYPROV_ECDH_ES_V1_READY}（禁止单边 READY 被解释为完整能力，FW-SEC-DSN-CR-017 决策 3）。
 */
public class KeyprovCertificateProfileHealthIndicator implements HealthIndicator {

    /**
     * 能力未启用状态（区别于 NOT_READY：能力开关关闭）。
     */
    public static final Status DISABLED =
            new Status("DISABLED", "TBOX device certificate profile capability disabled");

    /**
     * 能力未就绪状态（区别于 DOWN：依赖未就绪但进程健康）。
     */
    public static final Status NOT_READY =
            new Status("NOT_READY", "TBOX device certificate profile capability not ready");

    private final CryptoProperties properties;
    private final KeyprovReadiness readiness;

    public KeyprovCertificateProfileHealthIndicator(CryptoProperties properties, KeyprovReadiness readiness) {
        this.properties = properties;
        this.readiness = readiness;
    }

    @Override
    public Health health() {
        if (properties == null || properties.getKeyprov() == null
                || !properties.getKeyprov().getCertificateProfile().isEnabled()) {
            return Health.status(DISABLED)
                    .withDetail("capability", "crypto.keyprov.certificate-profile")
                    .withDetail("enabled", false)
                    .withDetail("capabilityId",
                            KeyprovCertificateProfileCapability.TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1)
                    .build();
        }
        if (readiness == null) {
            return Health.status(NOT_READY)
                    .withDetail("capability", "crypto.keyprov.certificate-profile")
                    .withDetail("enabled", true)
                    .withDetail("reason", "keyprov readiness is not wired")
                    .build();
        }
        String certificateReason = readiness.keyprovCertificateReadyReason();
        String aggregateReason = readiness.keyprovEcdhEsV1ReadyReason();
        boolean certificateReady = certificateReason == null;
        boolean aggregateReady = aggregateReason == null;
        Health.Builder builder;
        if (certificateReady && aggregateReady) {
            builder = Health.up();
        } else if (certificateReady) {
            builder = Health.status(NOT_READY).withDetail("aggregateReason", aggregateReason);
        } else {
            builder = Health.status(NOT_READY).withDetail("reason", certificateReason);
        }
        return builder
                .withDetail("capability", "crypto.keyprov.certificate-profile")
                .withDetail("enabled", true)
                .withDetail("capabilityId",
                        KeyprovCertificateProfileCapability.TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1)
                .withDetail("keyprovCertificateReady", certificateReady)
                .withDetail("keyprovEcdhEsV1Ready", aggregateReady)
                .build();
    }
}
