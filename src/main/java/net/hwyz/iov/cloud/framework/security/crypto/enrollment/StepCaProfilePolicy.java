package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * step-ca 签发策略（FW-SEC-DSN-CR-008 §7）
 * <p>
 * 将 framework 治理的 {@code CertificateProfile} 映射为 step-ca 侧的固定约束：
 * provisioner、kid、最大有效期、允许密钥算法、要求 EKU、主体规则。
 * 不同模板/授权边界优先使用不同 provisioner 或 CA 侧固定 template，
 * 业务不得任意传模板。
 *
 * @param profileName           framework profile 名（registry 键）
 * @param provisioner           step-ca provisioner 名
 * @param kid                   provisioner JWK 的 kid
 * @param maxValidity           最大签发有效期（null 表示不限制，受 step-ca 模板约束）
 * @param allowedKeyAlgorithms  允许的密钥算法（如 EC_P256）
 * @param requiredEku           要求的扩展密钥用法（如 CLIENT_AUTH）
 * @param subjectRule           主体规则（如 TBOX：subject/SAN 必须以该前缀为界）
 */
public record StepCaProfilePolicy(
        String profileName,
        String provisioner,
        String kid,
        Duration maxValidity,
        List<String> allowedKeyAlgorithms,
        List<String> requiredEku,
        String subjectRule
) {

    public StepCaProfilePolicy {
        Objects.requireNonNull(profileName, "profileName must not be null");
        Objects.requireNonNull(provisioner, "provisioner must not be null");
        Objects.requireNonNull(allowedKeyAlgorithms, "allowedKeyAlgorithms must not be null");
        Objects.requireNonNull(requiredEku, "requiredEku must not be null");
    }
}
