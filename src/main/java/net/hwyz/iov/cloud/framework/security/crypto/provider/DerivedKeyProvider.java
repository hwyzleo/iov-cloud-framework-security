package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;

/**
 * DERIVED_ROOT 派生 Provider SPI（FW-SEC-DSN-CR-019 §5.1/RD-019-2）。
 * <p>
 * 首个实现为 {@code TransitDerivedKeyProvider}（Transit HMAC + 本地证书公钥 Wrap）；
 * 生产环境可通过同一 SPI 替换为原子 Derive+Wrap 的 KMS/HSM Provider，不改变业务门面。
 * RANDOM_MATERIAL 走独立随机材料 Provider，不并入本 SPI。
 */
public interface DerivedKeyProvider {

    /**
     * 派生并封装（FW-SEC-DSN-CR-019 §5.3）。
     * <p>
     * 派生明文只在 Provider 受控方法作用域内短暂存在，完成后尽力清零；
     * 结果只含 Wrapped Key、KCV、逻辑引用与版本元数据。
     *
     * @param command 受信派生命令（策略已校验）
     * @return 瞬时派生封装结果
     */
    DerivedWrappedKey deriveAndWrap(DerivedKeyCommand command);

    /**
     * Provider 能力快照（readiness/Health 门禁）。
     *
     * @return 能力快照
     */
    DerivedKeyCapability capability();
}
