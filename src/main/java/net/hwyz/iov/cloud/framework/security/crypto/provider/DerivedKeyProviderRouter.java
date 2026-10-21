package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;

import java.util.Objects;

/**
 * DERIVED_ROOT 派生 Provider 路由器（FW-SEC-DSN-CR-019 §4/RD-019-2）。
 * <p>
 * 只按受治理 {@code materialModel/BizType} 与<strong>启动静态配置</strong>选择实现；
 * VMD 不参与 Provider 选择。
 * <ul>
 *   <li>{@code openbao-transit-local-wrap} → {@code TransitDerivedKeyProvider}
 *       （首期仅 V2C_COMM_ROOT，其他 DERIVED_ROOT 由策略注册表 fail-closed）；</li>
 *   <li>{@code openbao-business-key} → 既有 Feign 路径（迁移兼容，已废弃）；</li>
 *   <li>未知值 → 启动 fail-closed。</li>
 * </ul>
 * <strong>禁止</strong>请求失败后动态回退到另一 Provider（禁双写/运行时自动切换，
 * FW-SEC-DSN-CR-019 §12）。RANDOM_MATERIAL 走独立随机材料 Provider，不进入本路由器。
 */
public class DerivedKeyProviderRouter {

    public static final String LOCAL_WRAP_PROVIDER = "openbao-transit-local-wrap";
    public static final String LEGACY_PROVIDER = "openbao-business-key";

    private final String providerValue;
    private final DerivedKeyProvider transitProvider;
    private final DerivedKeyProvider legacyProvider;

    /**
     * @param providerValue  启动静态 Provider 选择（未知值启动 fail-closed）
     * @param transitProvider 本地 Transit Provider（local-wrap 时必填，可为 null）
     * @param legacyProvider  legacy Feign Provider（business-key 时必填）
     */
    public DerivedKeyProviderRouter(String providerValue, DerivedKeyProvider transitProvider,
                                    DerivedKeyProvider legacyProvider) {
        this.providerValue = Objects.requireNonNull(providerValue, "providerValue must not be null");
        if (LOCAL_WRAP_PROVIDER.equals(providerValue)) {
            if (transitProvider == null) {
                throw new IllegalStateException(
                        "derived-key.provider=openbao-transit-local-wrap 但 TransitDerivedKeyProvider 未装配");
            }
            this.transitProvider = transitProvider;
            this.legacyProvider = null;
        } else if (LEGACY_PROVIDER.equals(providerValue)) {
            if (legacyProvider == null) {
                throw new IllegalStateException(
                        "derived-key.provider=openbao-business-key 但 legacy Provider 未装配");
            }
            this.transitProvider = null;
            this.legacyProvider = legacyProvider;
        } else {
            throw new IllegalStateException(
                    "crypto.provisioning.derived-key.provider 未知值: " + providerValue
                            + "（允许: " + LOCAL_WRAP_PROVIDER + " | " + LEGACY_PROVIDER + "）");
        }
    }

    public DerivedWrappedKey deriveAndWrap(DerivedKeyCommand command) {
        if (LOCAL_WRAP_PROVIDER.equals(providerValue)) {
            return transitProvider.deriveAndWrap(command);
        }
        return legacyProvider.deriveAndWrap(command);
    }

    public DerivedKeyCapability capability() {
        if (LOCAL_WRAP_PROVIDER.equals(providerValue)) {
            return transitProvider.capability();
        }
        return legacyProvider.capability();
    }

    public String providerName() {
        return providerValue;
    }
}
