package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * 派生上下文编码器（FW-SEC-DSN-CR-019 §6）。
 * <p>
 * <pre>
 * context = UTF8("{derivationLabel}|{derivationVersion}|{normalizedAnchor}|{purpose}")
 * </pre>
 * V2C 首期固定：
 * <pre>
 * openiov|v2c|{derivationVersion}|{normalizedVIN}|{purpose}
 * </pre>
 * 格式、分隔符与大小写形成固定测试向量；label 是受治理协议常量，不是可配置 keyName。
 * 输出是有界 byte[]，由 Provider 在 finally 中清零，禁止转为 String 持久化。
 */
public class DerivedKeyContextEncoder {

    /**
     * 编码派生上下文。
     *
     * @param policy            已校验派生策略（提供派生标签）
     * @param anchor            规范化锚点（value 已按规则规范化，VIN 为 17 位大写 ASCII）
     * @param purpose           派生用途
     * @param derivationVersion 派生版本
     * @return context 字节（UTF-8）
     */
    public byte[] encode(DerivedKeyPolicy policy, KeyAnchor anchor, KeyPurpose purpose,
                         String derivationVersion) {
        Objects.requireNonNull(policy, "policy must not be null");
        Objects.requireNonNull(anchor, "anchor must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        String context = policy.derivationLabel()
                + "|" + derivationVersion
                + "|" + anchor.value()
                + "|" + purpose.name();
        return context.getBytes(StandardCharsets.UTF_8);
    }
}
