package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceCertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * 已验证收方证书证据（FW-SEC-DSN-CR-019 §5.1，两级校验）。
 * <p>
 * 由门面在<strong>完整校验</strong>（证书解析、链验证、有效期、吊销状态、KU/EKU、Profile、
 * 主体绑定、指纹与套件推导）后生成的<strong>不可变</strong>证据；Provider 层只执行最终密码学
 * 门禁（存在且未过期、leaf DER/SPKI/指纹一致且非空、WrapMode 允许、SPKI 算法/曲线与套件匹配），
 * <strong>不再</strong>重新解析目录、查询 OCSP/CRL 或重跑整条证书链。
 * <p>
 * 所有 bytes 防御性复制；{@code toString()} 不回显 DER/SPKI/指纹原文。
 *
 * @param certificateSerial    设备证书序列号（门面解析后的最终值）
 * @param leafCertificateDer  叶子证书 DER
 * @param spki                收方公钥 SPKI DER
 * @param sha256Fingerprint   叶子证书 SHA-256 指纹（小写十六进制）
 * @param certificateProfile  通过的证书 Profile
 * @param validatedWrapSuite  由公钥算法推导的已验证封装套件（请求不得覆盖）
 * @param validatedAt         校验时刻
 * @param validUntil          证书有效期截止（Provider 最终门禁据此拒绝过期证据）
 * @param status              吊销状态（仅 {@code GOOD} 可进入派生）
 * @param subjectBindingDigest 主体绑定摘要（非敏感，用于幂等冲突检测）
 * @param requestId           证书所属 enrollment 请求标识（可空）
 */
public record ValidatedRecipientEvidence(
        String certificateSerial,
        byte[] leafCertificateDer,
        byte[] spki,
        String sha256Fingerprint,
        DeviceCertificateProfile certificateProfile,
        WrappingSuite validatedWrapSuite,
        Instant validatedAt,
        Instant validUntil,
        RecipientStatus status,
        String subjectBindingDigest,
        String requestId) {

    public ValidatedRecipientEvidence {
        Objects.requireNonNull(validatedWrapSuite, "validatedWrapSuite must not be null");
        Objects.requireNonNull(validatedAt, "validatedAt must not be null");
        Objects.requireNonNull(status, "status must not be null");
        if (status != RecipientStatus.GOOD) {
            throw new IllegalArgumentException("ValidatedRecipientEvidence status must be GOOD");
        }
        leafCertificateDer = cloneOrNull(leafCertificateDer);
        spki = cloneOrNull(spki);
    }

    private static byte[] cloneOrNull(byte[] value) {
        return value == null ? null : value.clone();
    }

    @Override
    public byte[] leafCertificateDer() {
        return cloneOrNull(leafCertificateDer);
    }

    @Override
    public byte[] spki() {
        return cloneOrNull(spki);
    }

    /**
     * 收方吊销状态：仅 GOOD 允许进入 Transit 派生封装。
     */
    public enum RecipientStatus {
        GOOD
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ValidatedRecipientEvidence that)) {
            return false;
        }
        return Objects.equals(certificateSerial, that.certificateSerial)
                && Arrays.equals(leafCertificateDer, that.leafCertificateDer)
                && Arrays.equals(spki, that.spki)
                && Objects.equals(sha256Fingerprint, that.sha256Fingerprint)
                && certificateProfile == that.certificateProfile
                && validatedWrapSuite == that.validatedWrapSuite
                && Objects.equals(validatedAt, that.validatedAt)
                && Objects.equals(validUntil, that.validUntil)
                && status == that.status
                && Objects.equals(subjectBindingDigest, that.subjectBindingDigest)
                && Objects.equals(requestId, that.requestId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(certificateSerial, sha256Fingerprint, certificateProfile,
                validatedWrapSuite, validatedAt, validUntil, status, subjectBindingDigest, requestId);
        result = 31 * result + Arrays.hashCode(leafCertificateDer);
        result = 31 * result + Arrays.hashCode(spki);
        return result;
    }

    /**
     * 非敏感描述：只输出 profile/套件/校验时刻，不回显 DER/SPKI/指纹。
     */
    @Override
    public String toString() {
        return "ValidatedRecipientEvidence{profile=" + certificateProfile
                + ", suite=" + validatedWrapSuite
                + ", validatedAt=" + validatedAt
                + ", validUntil=" + validUntil
                + ", status=" + status
                + ", leafDer=" + (leafCertificateDer == null ? "null" : "[" + leafCertificateDer.length + " bytes]")
                + ", spki=" + (spki == null ? "null" : "[" + spki.length + " bytes]") + '}';
    }
}
