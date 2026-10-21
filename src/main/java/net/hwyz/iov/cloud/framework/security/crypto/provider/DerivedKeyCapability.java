package net.hwyz.iov.cloud.framework.security.crypto.provider;

/**
 * 派生 Provider 能力快照（FW-SEC-DSN-CR-019 §10）。
 * <p>
 * 供 readiness/Health/VMD keyprov 门禁使用；未就绪时 capability 必须 DOWN，
 * 不得回退随机 Create、旧 Provider、Noop、本地随机密钥或明文降级。
 *
 * @param providerName   Provider 名（如 {@code openbao-transit-local-wrap}）
 * @param ready          是否就绪
 * @param notReadyReason 未就绪稳定 reason（READY 时为 null）
 */
public record DerivedKeyCapability(String providerName, boolean ready, String notReadyReason) {

    public static DerivedKeyCapability ready(String providerName) {
        return new DerivedKeyCapability(providerName, true, null);
    }

    public static DerivedKeyCapability down(String providerName, String reason) {
        return new DerivedKeyCapability(providerName, false, reason);
    }
}
