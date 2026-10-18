package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Objects;

/**
 * 派生上下文（FW-SEC-DSN-CR-013 §6/§9；FW-SEC-DSN-CR-014 §5.2）。
 * <p>
 * 承载受治理的 <strong>派生版本</strong>（{@code derivationVersion}）与 VMD 维护的
 * <strong>业务版本</strong>（{@code businessKeyVersion}）。派生版本表示派生格式，
 * 与 Transit/HSM {@code rootKeyVersion}、VMD {@code businessKeyVersion} 三者分离，互不代替。
 * 派生格式变化时提升 {@code derivationVersion}，不得隐式回退。
 * <p>
 * {@code businessKeyVersion} 参与 Provider 幂等请求摘要（§5.2）；调用方未提供时按 {@code 0}
 * 处理（摘要仍按声明值计算，不得由 framework 猜测替代）。
 * <p>
 * 具体派生标签与字节编码由 framework 治理（{@code KeyProvisioningTemplate}），业务不得自定义。
 *
 * @param derivationVersion  派生版本（首期固定 {@value #V1}）
 * @param businessKeyVersion VMD 业务版本（可空/缺省 0 表示未声明）
 */
public record DerivationContext(String derivationVersion, long businessKeyVersion) {

    /** 首期派生版本 */
    public static final String V1 = "v1";

    public DerivationContext {
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        if (derivationVersion.isBlank()) {
            throw new IllegalArgumentException("derivationVersion must not be blank");
        }
        if (businessKeyVersion < 0) {
            throw new IllegalArgumentException("businessKeyVersion must not be negative");
        }
    }

    /**
     * 仅派生版本（业务版本缺省 0）。
     *
     * @param derivationVersion 派生版本
     */
    public DerivationContext(String derivationVersion) {
        this(derivationVersion, 0L);
    }

    /**
     * 首期默认派生上下文（{@code v1}）。
     */
    public static DerivationContext v1() {
        return new DerivationContext(V1, 0L);
    }

    /**
     * 按给定版本构造。
     *
     * @param derivationVersion 派生版本
     * @return 派生上下文
     */
    public static DerivationContext of(String derivationVersion) {
        return new DerivationContext(derivationVersion, 0L);
    }

    /**
     * 按派生版本 + 业务版本构造。
     *
     * @param derivationVersion  派生版本
     * @param businessKeyVersion VMD 业务版本
     * @return 派生上下文
     */
    public static DerivationContext of(String derivationVersion, long businessKeyVersion) {
        return new DerivationContext(derivationVersion, businessKeyVersion);
    }
}
