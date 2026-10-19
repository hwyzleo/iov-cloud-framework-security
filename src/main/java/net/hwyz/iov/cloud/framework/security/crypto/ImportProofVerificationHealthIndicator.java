package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;

/**
 * 导入证明验签能力健康指标（FW-SEC-DSN-CR-016 §8）。
 * <p>
 * 表示「导入证明验签能力是否就绪」，不默认拖垮无关业务接口的全局 readiness；是否纳入 Health Group
 * 由消费方配置。
 * <ul>
 *   <li>未启用（{@code crypto.import-proof.enabled=false}）：{@link #DISABLED}；</li>
 *   <li>启用但自检/证书解析配置未就绪：{@link #NOT_READY}；</li>
 *   <li>启用且就绪：UP。</li>
 * </ul>
 * 仅供运维门禁使用；DOWN/NOT_READY 时<strong>不得</strong>向 VMD 声明 proof verification READY。
 */
public class ImportProofVerificationHealthIndicator implements HealthIndicator {

    /**
     * 能力未启用状态（区别于 NOT_READY：能力开关关闭）。
     */
    public static final Status DISABLED =
            new Status("DISABLED", "Import proof verification capability disabled");

    /**
     * 能力未就绪状态（区别于 DOWN：依赖未就绪但进程健康）。
     */
    public static final Status NOT_READY =
            new Status("NOT_READY", "Import proof verification capability not ready");

    private static final String CAPABILITY = "crypto.import-proof";

    private final CryptoProperties properties;
    private final ImportProofReadiness readiness;

    public ImportProofVerificationHealthIndicator(CryptoProperties properties,
                                                  ImportProofReadiness readiness) {
        this.properties = properties;
        this.readiness = readiness;
    }

    @Override
    public Health health() {
        if (properties == null || properties.getImportProof() == null
                || !properties.getImportProof().isEnabled()) {
            return Health.status(DISABLED)
                    .withDetail("capability", CAPABILITY)
                    .withDetail("enabled", false)
                    .build();
        }
        if (readiness == null) {
            return Health.status(NOT_READY)
                    .withDetail("capability", CAPABILITY)
                    .withDetail("enabled", true)
                    .withDetail("reason", "import-proof readiness is not wired")
                    .build();
        }
        String reason = readiness.notReadyReason();
        Health.Builder builder = reason == null
                ? Health.up()
                : Health.status(NOT_READY).withDetail("reason", reason);
        return builder
                .withDetail("capability", CAPABILITY)
                .withDetail("enabled", true)
                .withDetail("capabilityId", ImportProofCapability.IMPORT_PROOF_VERIFY_ECDSA_P256_V1)
                .build();
    }
}
