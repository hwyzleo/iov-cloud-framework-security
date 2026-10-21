package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import java.util.Objects;

/**
 * Profile → signer 解析后的有效路由（FW-SEC-DSN-CR-018 §6）。
 * <p>
 * 只由内部 effective route 产生，<strong>不进入业务 API</strong>（RD-018-3）。
 *
 * @param profileName framework Profile 名
 * @param provisioner 有效 provisioner（显式 signer 与 Profile 校验一致后取 signer；legacy 取 Profile）
 * @param kid         有效 kid（同上；JWS header.kid = effective route kid）
 * @param signerRef   选中的 signer 引用（显式或保留 {@link StepCaProfileRouteResolver#LEGACY_SIGNER_REF}）
 * @param policy      对应的 trusted Profile policy
 */
public record EffectiveStepCaProfileRoute(
        String profileName,
        String provisioner,
        String kid,
        String signerRef,
        StepCaProfilePolicy policy
) {

    public EffectiveStepCaProfileRoute {
        Objects.requireNonNull(profileName, "profileName must not be null");
        Objects.requireNonNull(provisioner, "provisioner must not be null");
        Objects.requireNonNull(signerRef, "signerRef must not be null");
        Objects.requireNonNull(policy, "policy must not be null");
        // kid 可为 null：路由未声明 kid 时由签名侧按 signer JWK kid 兜底
    }
}
