package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import java.util.Objects;

/**
 * 命名 JWK signer 描述（FW-SEC-DSN-CR-018 §6）。
 *
 * @param signerRef        稳定、非敏感的 signer 引用（map key；kid 可轮换且可能含不适宜作 YAML key 的字符，
 *                         不作为配置主键，RD-018-2）
 * @param provisioner      signer 绑定的 step-ca provisioner 名（legacy 单 JWK 为 null，由 Profile route 提供）
 * @param kid              signer 绑定的 provisioner JWK kid（legacy 单 JWK 为 null，由 Profile route 提供）
 * @param privateKeyHandle 不可变私钥句柄（{@code toString()} 不泄漏私钥参数）
 */
public record JwkSignerDescriptor(
        String signerRef,
        String provisioner,
        String kid,
        JwkPrivateKeyHandle privateKeyHandle
) {

    public JwkSignerDescriptor {
        Objects.requireNonNull(signerRef, "signerRef must not be null");
        Objects.requireNonNull(privateKeyHandle, "privateKeyHandle must not be null");
        // provisioner/kid 可为 null：仅 legacy 单 JWK（route 取自 Profile）
    }
}
