package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.auth.KmsAuthScope;
import net.hwyz.iov.cloud.framework.security.crypto.auth.OpenBaoTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.OpenBaoAuthenticationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.provider.CertificatePublicKeyWrapper;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCapability;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicy;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.TboxDeviceCertificateValidator;
import org.springframework.beans.factory.ObjectProvider;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * TransitDerivedKeyCapability 聚合就绪（FW-SEC-DSN-CR-019 §10）。
 * <p>
 * DERIVED_ROOT readiness 聚合（任一缺失/超预算/策略不匹配均 DOWN，绝不回退随机 Create、
 * 旧 Provider、Noop、本地随机密钥或明文降级；不再探测 {@code /v1/business-key/capabilities}）：
 * <ol>
 *   <li>OpenBao health/active/unsealed；</li>
 *   <li>AppRole 登录（短期 Token 只在认证组件内存）；</li>
 *   <li>Transit mount 与根元数据（404/503 分类）；</li>
 *   <li>HMAC 路径权限（固定输入试探，403 → HMAC_FORBIDDEN）；</li>
 *   <li>根类型、根版本与不可导出配置；</li>
 *   <li>Certificate Validator（TboxDeviceCertificateValidator Bean 已装配）；</li>
 *   <li>本地 Wrap 算法、JCA Provider 与 SecureRandom 自检；</li>
 *   <li>BizType 策略及 derivationVersion（编译期 allowlist 一致）。</li>
 * </ol>
 * business-key mount 404 只影响 RANDOM_MATERIAL capability，不再影响 DERIVED_ROOT。
 */
public class TransitDerivedKeyReadiness {

    /** 权限试探测输入（固定、非敏感） */
    private static final byte[] HMAC_PERMISSION_PROBE =
            "openiov-readiness-probe".getBytes(StandardCharsets.UTF_8);

    private final CryptoProperties properties;
    private final OpenBaoTokenProvider tokenProvider;
    private final TransitHmacClient transitHmacClient;
    private final CertificatePublicKeyWrapper wrapper;
    private final DerivedKeyPolicyRegistry policyRegistry;
    private final TransitRootMetadataCache rootMetadataCache;
    private final ObjectProvider<TboxDeviceCertificateValidator> certValidatorProvider;

    public TransitDerivedKeyReadiness(CryptoProperties properties,
                                      OpenBaoTokenProvider tokenProvider,
                                      TransitHmacClient transitHmacClient,
                                      CertificatePublicKeyWrapper wrapper,
                                      DerivedKeyPolicyRegistry policyRegistry,
                                      TransitRootMetadataCache rootMetadataCache,
                                      ObjectProvider<TboxDeviceCertificateValidator> certValidatorProvider) {
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.tokenProvider = Objects.requireNonNull(tokenProvider, "tokenProvider must not be null");
        this.transitHmacClient = Objects.requireNonNull(transitHmacClient, "transitHmacClient must not be null");
        this.wrapper = Objects.requireNonNull(wrapper, "wrapper must not be null");
        this.policyRegistry = Objects.requireNonNull(policyRegistry, "policyRegistry must not be null");
        this.rootMetadataCache = Objects.requireNonNull(rootMetadataCache, "rootMetadataCache must not be null");
        this.certValidatorProvider = certValidatorProvider;
    }

    /**
     * 未就绪稳定 reason；READY 返回 null。
     */
    public String notReadyReason() {
        // 维度 8：BizType 策略及 derivationVersion（编译期 allowlist + 配置一致，构造期已校验）
        DerivedKeyPolicy v2c = policyRegistry.policyFor(BizType.V2C_COMM_ROOT);
        if (v2c == null) {
            return "DERIVATION_POLICY_INVALID: V2C_COMM_ROOT 未登记 Transit 本地派生策略";
        }
        if (!Objects.equals(properties.getProvisioning().getDerivedKey().getDerivationVersion(),
                DerivedKeyPolicyRegistry.V2C_DERIVATION_VERSION)) {
            return "DERIVATION_POLICY_INVALID: derivationVersion 与编译期 allowlist 不一致";
        }

        // 维度 2：AppRole 登录
        try {
            tokenProvider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT);
        } catch (OpenBaoAuthenticationException e) {
            return "TRANSIT_AUTH_FAILED: AppRole 登录失败";
        } catch (Exception e) {
            return "TRANSIT_UNAVAILABLE: 认证组件不可用";
        }

        // 维度 1：OpenBao health/active/unsealed
        try {
            TransitSystemHealth health = transitHmacClient.probeHealth();
            if (!health.ready()) {
                return health.sealed() ? "TRANSIT_SEALED: OpenBao sealed"
                        : health.standby() ? "TRANSIT_UNAVAILABLE: OpenBao standby（非 active）"
                        : "TRANSIT_UNAVAILABLE: OpenBao 未初始化";
            }
        } catch (TransitException e) {
            return reasonOf(e);
        }

        // 维度 3/5：Transit mount 与根元数据（根类型/版本/不可导出）
        try {
            TransitKeyMetadata metadata = rootMetadataCache.validateAndCache(v2c.transitKeyName());
            if (metadata.exportable()) {
                return "TRANSIT_ROOT_TYPE_MISMATCH: 根密钥 exportable=true（DERIVED_ROOT 禁止导出）";
            }
            if (!metadata.isAesHmacCompatible()) {
                return "TRANSIT_ROOT_TYPE_MISMATCH: 根密钥类型不支持 HMAC 派生: " + metadata.type();
            }
        } catch (TransitException e) {
            return reasonOf(e);
        }

        // 维度 4：HMAC 路径权限（固定输入试探，403 → HMAC_FORBIDDEN）
        try {
            transitHmacClient.hmac(v2c.transitKeyName(), v2c.hmacAlgorithm(), HMAC_PERMISSION_PROBE,
                    new OperationContext("readiness-probe", "readiness-probe"));
        } catch (TransitException e) {
            if (e.transitReason() == net.hwyz.iov.cloud.framework.security.crypto.exception.TransitReason.TRANSIT_HMAC_FORBIDDEN) {
                return "TRANSIT_HMAC_FORBIDDEN: HMAC 路径权限不足";
            }
            return reasonOf(e);
        }

        // 维度 6：Certificate Validator Bean
        if (certValidatorProvider == null || certValidatorProvider.getIfAvailable() == null) {
            return "RECIPIENT_CERTIFICATE_INVALID: TboxDeviceCertificateValidator 未装配";
        }

        // 维度 7：本地 Wrap 算法、JCA Provider 与 SecureRandom
        if (!localWrapSelfCheck()) {
            return "WRAP_ALGORITHM_UNAVAILABLE: 本地 Wrap 算法/JCA Provider/SecureRandom 自检失败";
        }
        return null;
    }

    /**
     * 聚合能力快照。
     */
    public DerivedKeyCapability capability() {
        String reason = notReadyReason();
        return reason == null
                ? DerivedKeyCapability.ready(TransitDerivedKeyProvider.PROVIDER_NAME)
                : DerivedKeyCapability.down(TransitDerivedKeyProvider.PROVIDER_NAME, reason);
    }

    public boolean isReady() {
        return notReadyReason() == null;
    }

    /**
     * 启动门禁：未 READY 抛异常使启动 fail-closed。
     */
    public void verifyAtStartup() {
        String reason = notReadyReason();
        if (reason != null) {
            throw new IllegalStateException(
                    "TransitDerivedKey capability 未 READY，启动 fail-closed"
                            + "（FW-SEC-DSN-CR-019 §10）: " + reason);
        }
    }

    private static String reasonOf(TransitException e) {
        return e.transitReason().wireName() + ": " + e.getMessage();
    }

    /**
     * JCA 本地 Wrap 自检：P-256 ECDH、AES-256-GCM、RSA-OAEP-SHA256 与 SecureRandom 可用。
     */
    private static boolean localWrapSelfCheck() {
        try {
            KeyPairGenerator.getInstance("EC").initialize(
                    new java.security.spec.ECGenParameterSpec("secp256r1"));
            javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            byte[] random = new byte[8];
            new SecureRandom().nextBytes(random);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
