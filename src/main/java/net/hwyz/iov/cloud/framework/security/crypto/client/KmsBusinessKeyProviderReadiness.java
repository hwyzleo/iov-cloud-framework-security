package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * 业务密钥 Provider 能力门禁与就绪状态（FW-SEC-DSN-CR-011 §7/§8.3）。
 * <p>
 * 启动时探测 {@link KmsClient#getCapabilities()} 并校验 Provider 身份、API 版本、mount、
 * storage/mount 状态与必需 WrapMode；任一不匹配或未就绪即 fail-closed（启动失败或 readiness DOWN）。
 * <p>
 * mount/api-version/capability-path 均为契约期望值，仅用于校验，不参与运行时 URL 拼接或重写。
 */
public class KmsBusinessKeyProviderReadiness {

    private static final Logger log = LoggerFactory.getLogger(KmsBusinessKeyProviderReadiness.class);

    /**
     * 编译期固定的 capability wire 路径；配置 capability-path 必须与此一致。
     */
    public static final String EXPECTED_CAPABILITY_PATH = "/v1/business-key/capabilities";

    /**
     * 首期必需的 WrapMode（设备证书公钥封装，keyprov 闭环依赖）。
     */
    public static final String REQUIRED_WRAP_MODE = WrapMode.DEVICE_CERT_PUBLIC_KEY.name();

    /**
     * 派生封装（deriveAndWrap）必需的信封版本（FW-SEC-DSN-CR-014 §9）。
     */
    public static final String REQUIRED_DERIVED_ENVELOPE_VERSION = "v1";

    /**
     * 派生封装（deriveAndWrap）必需的密码学能力标记（FW-SEC-DSN-CR-014 §9）。
     */
    public static final java.util.List<String> REQUIRED_DERIVED_ALGORITHMS =
            java.util.List.of("ECDH_P256", "HKDF_SHA256", "AES_256_GCM");

    private final KmsClient kmsClient;
    private final CryptoProperties properties;
    private final CryptoMetrics cryptoMetrics;

    private volatile KmsProviderCapabilities capabilities = KmsProviderCapabilities.down();
    private volatile boolean ready = false;
    private volatile String reason = "not probed";

    public KmsBusinessKeyProviderReadiness(KmsClient kmsClient, CryptoProperties properties,
                                           CryptoMetrics cryptoMetrics) {
        this.kmsClient = kmsClient;
        this.properties = properties;
        this.cryptoMetrics = cryptoMetrics;
    }

    /**
     * 启动门禁：探测并校验能力；未 READY 抛异常使应用启动 fail-closed。
     */
    public void verifyAtStartup() {
        if (!probe()) {
            throw new IllegalStateException(
                    "业务密钥 Provider capability 未 READY，启动 fail-closed（FW-SEC-DSN-CR-011 §7/§11）: " + reason);
        }
    }

    /**
     * 探测并刷新 Provider 能力状态；失败/不匹配返回 false 且不抛异常（调用方按需 fail-closed）。
     */
    public synchronized boolean probe() {
        try {
            KmsProviderCapabilities caps = kmsClient.getCapabilities();
            this.capabilities = caps != null ? caps : KmsProviderCapabilities.down();
            String mismatch = mismatchReason(this.capabilities);
            if (mismatch != null) {
                this.ready = false;
                this.reason = mismatch;
                log.warn("业务密钥 Provider capability 配置不匹配: {}", mismatch);
                return false;
            }
            if (!this.capabilities.isReady()) {
                this.ready = false;
                this.reason = "provider storage/mount not ready";
                log.warn("业务密钥 Provider capability 未就绪: provider={}, storageReady={}, mountReady={}",
                        this.capabilities.provider(), this.capabilities.storageReady(),
                        this.capabilities.mountReady());
                return false;
            }
            if (!this.capabilities.supportsWrapMode(REQUIRED_WRAP_MODE)) {
                this.ready = false;
                this.reason = "required wrap mode not supported: " + REQUIRED_WRAP_MODE;
                log.warn("业务密钥 Provider 缺少必需 WrapMode: {}", REQUIRED_WRAP_MODE);
                return false;
            }
            // 派生封装（deriveAndWrap）READY 门禁：仅当该门面启用时校验（FW-SEC-DSN-CR-014 §9）。
            if (properties.getProvisioning().isEnabled()) {
                String derivedMismatch = derivedReadinessReason(this.capabilities);
                if (derivedMismatch != null) {
                    this.ready = false;
                    this.reason = derivedMismatch;
                    log.warn("deriveAndWrap Provider capability 未就绪: {}", derivedMismatch);
                    return false;
                }
            }
            this.ready = true;
            this.reason = "ready";
            log.info("业务密钥 Provider capability READY: provider={}, apiVersion={}, mount={}, wrapModes={}",
                    this.capabilities.provider(), this.capabilities.apiVersion(),
                    this.capabilities.mount(), this.capabilities.wrapModes());
            return true;
        } catch (Exception e) {
            this.capabilities = KmsProviderCapabilities.down();
            this.ready = false;
            this.reason = "capability probe failed: " + e.getMessage();
            log.warn("业务密钥 Provider capability 探测失败: {}", e.getMessage());
            return false;
        }
    }

    private String mismatchReason(KmsProviderCapabilities caps) {
        CryptoProperties.Kms kms = properties.getKms();
        CryptoProperties.Kms.BusinessKey cfg = kms.getBusinessKey();

        if (caps.provider() == null || !caps.provider().equals(kms.getProvider())) {
            return "provider mismatch: expected=" + kms.getProvider() + ", actual=" + caps.provider();
        }
        if (caps.apiVersion() == null || !caps.apiVersion().equals(cfg.getApiVersion())) {
            return "api-version mismatch: expected=" + cfg.getApiVersion() + ", actual=" + caps.apiVersion();
        }
        if (caps.mount() == null || !caps.mount().equals(cfg.getMount())) {
            return "mount mismatch: expected=" + cfg.getMount() + ", actual=" + caps.mount();
        }
        if (!Objects.equals(cfg.getCapabilityPath(), EXPECTED_CAPABILITY_PATH)) {
            return "capability-path mismatch: expected=" + EXPECTED_CAPABILITY_PATH
                    + ", actual=" + cfg.getCapabilityPath();
        }
        return null;
    }

    /**
     * deriveAndWrap READY 门禁（FW-SEC-DSN-CR-014 §9）：要求结果存储就绪、envelope v1 与
     * P-256 ECDH / HKDF-SHA-256 / AES-256-GCM capability 可用。任一不满足即 DOWN。
     */
    private String derivedReadinessReason(KmsProviderCapabilities caps) {
        if (!caps.resultStoreReady()) {
            return "operation result store not ready (encrypted envelope TTL/idempotency unavailable)";
        }
        if (!caps.supportsDerivedEnvelope(REQUIRED_DERIVED_ENVELOPE_VERSION)) {
            return "derived envelope version not supported: " + REQUIRED_DERIVED_ENVELOPE_VERSION;
        }
        for (String algorithm : REQUIRED_DERIVED_ALGORITHMS) {
            if (!caps.supportsAlgorithm(algorithm)) {
                return "required deriveAndWrap algorithm not supported: " + algorithm;
            }
        }
        return null;
    }

    public boolean isReady() {
        return ready;
    }

    public String getReason() {
        return reason;
    }

    public KmsProviderCapabilities getCapabilities() {
        return capabilities;
    }
}
