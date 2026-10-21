package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

import java.util.Set;

/**
 * 已校验派生策略（FW-SEC-DSN-CR-019 RD-019-3/§5.3）。
 * <p>
 * BizType 策略注册表是 rootRef、派生标签、允许 purpose、派生版本与 WrapMode 的
 * <strong>唯一来源</strong>；请求不得覆盖根名、Transit Key、HMAC 或封装算法。
 * <p>
 * 派生标签是受治理的协议常量（如 {@code openiov|v2c}），<strong>不</strong>直接把可配置
 * keyName 拼入 context；不同根（IMMO/OTA/设备根）后续分别固定独立标签后再逐步开放。
 *
 * @param bizType           业务类型
 * @param transitKeyName    批准的 Transit 根密钥名（如 {@code v2c-comm-root}）
 * @param hmacAlgorithm     Transit HMAC 算法（首期 {@code sha2-256}）
 * @param derivationLabel   受治理派生标签（协议常量）
 * @param allowedPurposes   允许的派生用途
 * @param allowedWrapSuites 允许的封装套件
 * @param derivationVersion 允许的派生版本
 */
public record DerivedKeyPolicy(
        BizType bizType,
        String transitKeyName,
        String hmacAlgorithm,
        String derivationLabel,
        Set<KeyPurpose> allowedPurposes,
        Set<WrappingSuite> allowedWrapSuites,
        String derivationVersion) {

    public DerivedKeyPolicy {
        if (bizType == null || transitKeyName == null || hmacAlgorithm == null
                || derivationLabel == null || allowedPurposes == null || allowedWrapSuites == null
                || derivationVersion == null) {
            throw new IllegalArgumentException("DerivedKeyPolicy fields must not be null");
        }
        allowedPurposes = Set.copyOf(allowedPurposes);
        allowedWrapSuites = Set.copyOf(allowedWrapSuites);
    }
}
