package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileNotAllowedException;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * step-ca profile 策略注册表（FW-SEC-DSN-CR-008 §7）
 * <p>
 * 只接受 framework 已注册的 {@code CertificateProfile} 对应的固定映射；
 * 未映射的 profile 在 step-ca 模式下整体 fail-closed 拒绝。
 */
public class StepCaProfilePolicyRegistry {

    private final Map<String, StepCaProfilePolicy> policies;

    public StepCaProfilePolicyRegistry(Map<String, StepCaProfilePolicy> policies) {
        Map<String, StepCaProfilePolicy> copy = new LinkedHashMap<>();
        if (policies != null) {
            copy.putAll(policies);
        }
        this.policies = Collections.unmodifiableMap(copy);
    }

    /**
     * 解析 profile 对应的 step-ca 策略；未注册则拒绝。
     *
     * @param profileName framework CertificateProfile 名
     * @return 固定策略
     */
    public StepCaProfilePolicy resolve(String profileName) {
        Objects.requireNonNull(profileName, "profileName must not be null");
        StepCaProfilePolicy policy = policies.get(profileName);
        if (policy == null) {
            throw new CertificateProfileNotAllowedException(
                    "No step-ca policy registered for profile: " + profileName);
        }
        return policy;
    }

    /**
     * 已注册的 profile 名集合。
     */
    public java.util.Set<String> profileNames() {
        return policies.keySet();
    }
}
