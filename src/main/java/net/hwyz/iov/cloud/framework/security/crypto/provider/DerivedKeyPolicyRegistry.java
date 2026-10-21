package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * BizType 派生策略注册表（FW-SEC-DSN-CR-019 RD-019-3/§5.3/§8）。
 * <p>
 * 编译期 allowlist 是唯一权威：首期仅登记 V2C_COMM_ROOT（transit-key={@code v2c-comm-root}、
 * HMAC={@code sha2-256}、标签={@code openiov|v2c}、purpose={@code UPLINK_AEAD/DOWNLINK_AEAD}、
 * WrapMode={@code DEVICE_CERT_PUBLIC_KEY}）。其他 DERIVED_ROOT 不得复用 V2C 标签；
 * 逐个开放时分别固定独立协议标签。
 * <p>
 * 配置根映射必须与本 allowlist 一致（见 {@link #validateConfig}），Nacos 或调用请求
 * <strong>不能新增任意 Transit Key</strong>。
 */
public class DerivedKeyPolicyRegistry {

    /** V2C 派生标签（受治理协议常量，不是可配置 keyName） */
    public static final String V2C_DERIVATION_LABEL = "openiov|v2c";
    /** V2C 首期派生版本 */
    public static final String V2C_DERIVATION_VERSION = "v1";

    private static final Map<BizType, DerivedKeyPolicy> ALLOWLIST = new EnumMap<>(BizType.class);

    static {
        ALLOWLIST.put(BizType.V2C_COMM_ROOT, new DerivedKeyPolicy(
                BizType.V2C_COMM_ROOT,
                "v2c-comm-root",
                "sha2-256",
                V2C_DERIVATION_LABEL,
                Set.of(KeyPurpose.UPLINK_AEAD, KeyPurpose.DOWNLINK_AEAD),
                Set.of(WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM),
                V2C_DERIVATION_VERSION));
    }

    /**
     * 校验命令并返回批准策略；非法即抛 {@link TransitException#policyInvalid}。
     *
     * @param command 受信派生命令
     * @return 已校验策略
     */
    public DerivedKeyPolicy validate(DerivedKeyCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        DerivedKeyPolicy policy = ALLOWLIST.get(command.bizType());
        if (policy == null) {
            throw TransitException.policyInvalid(
                    "bizType=" + command.bizType().name()
                            + " 未登记 Transit 本地派生策略（首期仅 V2C_COMM_ROOT）");
        }
        if (!policy.allowedPurposes().contains(command.purpose())) {
            throw TransitException.policyInvalid(
                    "purpose=" + command.purpose() + " 不允许 for bizType=" + command.bizType().name()
                            + " (allowed=" + policy.allowedPurposes() + ")");
        }
        if (!Objects.equals(policy.derivationVersion(), command.context().derivationVersion())) {
            throw TransitException.policyInvalid(
                    "derivationVersion=" + command.context().derivationVersion()
                            + " 不允许（策略固定 " + policy.derivationVersion() + "）");
        }
        if (!policy.allowedWrapSuites().contains(command.recipient().validatedWrapSuite())) {
            throw TransitException.policyInvalid(
                    "validatedWrapSuite=" + command.recipient().validatedWrapSuite()
                            + " 不允许 for bizType=" + command.bizType().name()
                            + " (allowed=" + policy.allowedWrapSuites() + ")");
        }
        return policy;
    }

    /**
     * 查询登记策略（未登记返回 null）。
     *
     * @param bizType 业务类型
     * @return 策略或 null
     */
    public DerivedKeyPolicy policyFor(BizType bizType) {
        return ALLOWLIST.get(bizType);
    }

    /**
     * 启动一致性校验：配置根映射必须与编译期 allowlist 一致（FW-SEC-DSN-CR-019 §8）。
     * <p>
     * provider=openbao-transit-local-wrap 时 V2C_COMM_ROOT 配置缺省/不一致即启动 fail-closed；
     * 配置不得引入 allowlist 之外的根（Nacos 不能新增任意 Transit Key）。
     *
     * @param derivationVersion 配置的派生版本
     * @param rootsConfig       配置根映射
     * @param rootPolicy        V2C 配置根策略（可为 null）
     */
    public static void validateConfig(String derivationVersion,
                                      Map<String, ?> rootsConfig,
                                      net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties.Provisioning.DerivedKey.RootPolicy rootPolicy) {
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        if (!Objects.equals(derivationVersion, V2C_DERIVATION_VERSION)) {
            throw new IllegalStateException(
                    "crypto.provisioning.derived-key.derivation-version=" + derivationVersion
                            + " 与编译期 allowlist 不一致（必须为 " + V2C_DERIVATION_VERSION + "）");
        }
        if (rootPolicy == null) {
            throw new IllegalStateException(
                    "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT 缺失："
                            + "openbao-transit-local-wrap 需要登记 V2C_COMM_ROOT 根映射");
        }
        if (!"v2c-comm-root".equals(rootPolicy.getTransitKey())) {
            throw new IllegalStateException(
                    "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.transit-key 必须为 v2c-comm-root，"
                            + "got " + rootPolicy.getTransitKey());
        }
        if (!"sha2-256".equals(rootPolicy.getHmacAlgorithm())) {
            throw new IllegalStateException(
                    "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.hmac-algorithm 必须为 sha2-256");
        }
        Set<String> purposes = Set.copyOf(rootPolicy.getPurposes() == null
                ? java.util.List.of() : rootPolicy.getPurposes());
        if (!purposes.equals(Set.of("UPLINK_AEAD", "DOWNLINK_AEAD"))) {
            throw new IllegalStateException(
                    "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.purposes 必须为 "
                            + "[UPLINK_AEAD, DOWNLINK_AEAD]");
        }
        Set<String> wrapModes = Set.copyOf(rootPolicy.getWrapModes() == null
                ? java.util.List.of() : rootPolicy.getWrapModes());
        if (!wrapModes.equals(Set.of("DEVICE_CERT_PUBLIC_KEY"))) {
            throw new IllegalStateException(
                    "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.wrap-modes 必须为 "
                            + "[DEVICE_CERT_PUBLIC_KEY]");
        }
        // 配置不允许登记 allowlist 之外的根（首期仅 V2C_COMM_ROOT）
        for (String rootName : rootsConfig.keySet()) {
            if (!"V2C_COMM_ROOT".equals(rootName)) {
                throw new IllegalStateException(
                        "crypto.provisioning.derived-key.roots." + rootName
                                + " 不在编译期 allowlist 中：Nacos/调用请求不能新增任意 Transit Key"
                                + "（首期仅 V2C_COMM_ROOT，其他 DERIVED_ROOT 逐步独立开放）");
            }
        }
    }
}
