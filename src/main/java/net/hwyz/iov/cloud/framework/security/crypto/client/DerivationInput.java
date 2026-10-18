package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

import java.util.Objects;

/**
 * 根派生输入（FW-SEC-DSN-CR-013 §7.3；FW-SEC-DSN-CR-014 §5.2）。
 * <p>
 * 由 {@code KeyProvisioningTemplate} 受治理地组装后传入 {@link KmsClient#deriveAndWrap}：
 * 锚点携带<strong>规范化原文</strong>（Provider 据此重算 HMAC 与摘要），purpose 与派生版本
 * 构成派生上下文的域隔离。anchor 摘要不参与派生，仅用于完整性比对。
 * <p>
 * {@code wrappingSuite} 由 framework 依据收方证书公钥算法推导（EC→ECDH-ES / RSA→RSA-OAEP）；
 * {@code requestId}/{@code businessDomain}/{@code businessKeyVersion} 参与 Provider 幂等请求摘要
 * （FW-SEC-DSN-CR-014 §5.2），缺省时按声明值（空/0）计算，不得由 framework 猜测替代。
 *
 * @param anchor             派生锚点（含规范化原文与摘要）
 * @param purpose            受治理派生用途（UPLINK_AEAD / DOWNLINK_AEAD）
 * @param derivationVersion  派生格式版本（首期 {@code v1}）
 * @param wrappingSuite      封装套件（由收方公钥算法推导，可空表示未声明）
 * @param requestId          请求标识（可空）
 * @param businessDomain     业务域（可空）
 * @param businessKeyVersion VMD 业务版本（缺省 0）
 */
public record DerivationInput(
        KeyAnchor anchor,
        KeyPurpose purpose,
        String derivationVersion,
        WrappingSuite wrappingSuite,
        String requestId,
        String businessDomain,
        long businessKeyVersion) {

    public DerivationInput {
        Objects.requireNonNull(anchor, "anchor must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        if (derivationVersion.isBlank()) {
            throw new IllegalArgumentException("derivationVersion must not be blank");
        }
        if (businessKeyVersion < 0) {
            throw new IllegalArgumentException("businessKeyVersion must not be negative");
        }
    }

    /**
     * 向后兼容构造：仅锚点/purpose/派生版本（无套件与幂等上下文）。
     *
     * @param anchor            派生锚点
     * @param purpose           派生用途
     * @param derivationVersion 派生版本
     */
    public DerivationInput(KeyAnchor anchor, KeyPurpose purpose, String derivationVersion) {
        this(anchor, purpose, derivationVersion, null, null, null, 0L);
    }
}
