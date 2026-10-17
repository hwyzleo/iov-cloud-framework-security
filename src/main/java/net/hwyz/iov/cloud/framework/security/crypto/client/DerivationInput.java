package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

import java.util.Objects;

/**
 * 根派生输入（FW-SEC-DSN-CR-013 §7.3）。
 * <p>
 * 由 {@code KeyProvisioningTemplate} 受治理地组装后传入 {@link KmsClient#deriveAndWrap}：
 * 锚点携带<strong>规范化原文</strong>（Provider 据此重算 HMAC 与摘要），purpose 与派生版本
 * 构成派生上下文的域隔离。anchor 摘要不参与派生，仅用于完整性比对。
 *
 * @param anchor            派生锚点（含规范化原文与摘要）
 * @param purpose           受治理派生用途（UPLINK_AEAD / DOWNLINK_AEAD）
 * @param derivationVersion 派生格式版本（首期 {@code v1}）
 */
public record DerivationInput(KeyAnchor anchor, KeyPurpose purpose, String derivationVersion) {

    public DerivationInput {
        Objects.requireNonNull(anchor, "anchor must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        if (derivationVersion.isBlank()) {
            throw new IllegalArgumentException("derivationVersion must not be blank");
        }
    }
}
