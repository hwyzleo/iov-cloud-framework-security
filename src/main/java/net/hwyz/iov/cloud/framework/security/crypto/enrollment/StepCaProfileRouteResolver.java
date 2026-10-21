package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import java.util.Objects;

/**
 * Profile → signer 路由解析（FW-SEC-DSN-CR-018 §7）。
 * <p>
 * 两级路由：逻辑 Profile 经 policy 授权后解析到唯一命名 signer（RD-018-3）；
 * 调用请求不能直接选择 signer。
 * <ul>
 *   <li>未声明 {@code jwk-signer-ref} 的 Profile 使用保留 legacy route（RD-018-4）；
 *       legacy 单 JWK 不存在时启动失败；</li>
 *   <li>Profile 显式引用 signer 时，二者 provisioner/kid 必须一致，冲突不得以任一方覆盖
 *       （RD-018-5）。</li>
 * </ul>
 */
public final class StepCaProfileRouteResolver {

    /**
     * legacy 单 JWK 的内部保留 signer 引用（不允许被用户用作 signer map key）。
     */
    public static final String LEGACY_SIGNER_REF = "__legacy__";

    private StepCaProfileRouteResolver() {
    }

    /**
     * 解析 policy 对应的有效路由：resolve signerRef（显式或 {@link #LEGACY_SIGNER_REF}）
     * → {@link JwkSignerRegistry#require} → RD-018-5 route 一致性校验。
     *
     * @param policy        已授权的 Profile policy
     * @param signerRegistry 命名 signer 注册表
     * @return 有效路由（provisioner/kid/signerRef 均已定案）
     * @throws IllegalStateException signer 缺失或 route 冲突（fail-closed）
     */
    public static EffectiveStepCaProfileRoute resolve(StepCaProfilePolicy policy,
                                                      JwkSignerRegistry signerRegistry) {
        Objects.requireNonNull(policy, "policy must not be null");
        Objects.requireNonNull(signerRegistry, "signerRegistry must not be null");

        String signerRef = policy.jwkSignerRef() == null || policy.jwkSignerRef().isBlank()
                ? LEGACY_SIGNER_REF
                : policy.jwkSignerRef().trim();
        JwkSignerDescriptor signer = signerRegistry.require(signerRef);

        // RD-018-5：signer 显式声明 provisioner/kid 时，必须与 Profile route 一致
        String provisioner = policy.provisioner();
        String kid = policy.kid();
        if (signer.provisioner() != null) {
            if (!signer.provisioner().equals(policy.provisioner())) {
                throw new IllegalStateException(
                        "signer route mismatch (RD-018-5): profile=" + policy.profileName()
                                + " provisioner='" + policy.provisioner() + "' != signer '" + signerRef
                                + "' provisioner='" + signer.provisioner()
                                + "'; conflict must not be resolved by overriding either side");
            }
            provisioner = signer.provisioner();
        }
        if (signer.kid() != null) {
            if (!signer.kid().equals(policy.kid())) {
                throw new IllegalStateException(
                        "signer route mismatch (RD-018-5): profile=" + policy.profileName()
                                + " kid='" + policy.kid() + "' != signer '" + signerRef + "' kid='"
                                + signer.kid() + "'; conflict must not be resolved by overriding either side");
            }
            kid = signer.kid();
        }
        return new EffectiveStepCaProfileRoute(policy.profileName(), provisioner, kid, signerRef, policy);
    }
}
