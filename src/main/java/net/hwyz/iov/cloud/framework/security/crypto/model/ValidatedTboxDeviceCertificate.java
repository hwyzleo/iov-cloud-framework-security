package net.hwyz.iov.cloud.framework.security.crypto.model;

import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * 结构化 TBOX 设备证书验证结果（FW-SEC-DSN-CR-017 §4）。
 * <p>
 * 统一 Profile 校验通过后的<strong>不可变证据</strong>，作为 CR-014 deriveAndWrap 与
 * CR-016 ImportProofVerifier 的共同证书事实源（RD-017-2）。
 * <p>
 * <strong>安全边界</strong>：
 * <ul>
 *   <li>{@code certificatePolicyDigest} 构造与访问均防御性复制；</li>
 *   <li>{@link #toString()}、异常与日志<strong>不</strong>输出 DER、公钥编码、完整摘要、
 *       serial 或设备身份（CR-017 §4 约束）；</li>
 *   <li>{@code publicKey} 仅用于 framework 内密码操作，<strong>不</strong>跨协议层序列化；</li>
 *   <li>验证时刻与状态 freshness 均由框架受控 {@link java.time.Clock} 提供，调用方不得注入。</li>
 * </ul>
 *
 * @param profile               验证通过的 Profile（首期恒为 TBOX_DEVICE_ECDH_ES_P256_V1）
 * @param certificateRef        解析/验证所用证书引用（含证据来源）
 * @param publicKey             叶子证书公钥（仅 framework 内部使用）
 * @param certificatePolicyDigest 证书绑定摘要 = SHA-256(leafCertificateDER)。
 *                               <strong>语义不变</strong>：沿用 wire 摘要（request digest /
 *                               canonical AAD / envelope / ACK 均按 leaf DER 复算绑定，
 *                               FW-SEC-DSN-CR-017 决策 1），仅作 framework 内部
 *                               CR-014/016 共享绑定比较，不产生第二套 policy digest。
 * @param p256                  公钥是否为 NIST P-256
 * @param digitalSignature      KeyUsage 是否含 digitalSignature
 * @param keyAgreement          KeyUsage 是否含 keyAgreement
 * @param clientAuth            EKU 是否含 clientAuth（且无冲突）
 * @param validatedAt           受控 Clock 的验证时刻
 * @param statusFreshUntil      吊销状态 freshness 截止（来自 status 响应 nextUpdate；
 *                               {@code null} 仅表示不可缓存，不代表状态永久有效）
 */
public record ValidatedTboxDeviceCertificate(
        DeviceCertificateProfile profile,
        DeviceCertificateRef certificateRef,
        PublicKey publicKey,
        byte[] certificatePolicyDigest,
        boolean p256,
        boolean digitalSignature,
        boolean keyAgreement,
        boolean clientAuth,
        Instant validatedAt,
        Instant statusFreshUntil) {

    public ValidatedTboxDeviceCertificate {
        Objects.requireNonNull(profile, "profile must not be null");
        Objects.requireNonNull(certificateRef, "certificateRef must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        Objects.requireNonNull(validatedAt, "validatedAt must not be null");
        certificatePolicyDigest = certificatePolicyDigest == null ? null : certificatePolicyDigest.clone();
    }

    @Override
    public byte[] certificatePolicyDigest() {
        return certificatePolicyDigest == null ? null : certificatePolicyDigest.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ValidatedTboxDeviceCertificate that)) {
            return false;
        }
        return p256 == that.p256
                && digitalSignature == that.digitalSignature
                && keyAgreement == that.keyAgreement
                && clientAuth == that.clientAuth
                && profile == that.profile
                && Objects.equals(certificateRef, that.certificateRef)
                && Objects.equals(publicKey, that.publicKey)
                && Arrays.equals(certificatePolicyDigest, that.certificatePolicyDigest)
                && Objects.equals(validatedAt, that.validatedAt)
                && Objects.equals(statusFreshUntil, that.statusFreshUntil);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(profile, certificateRef, publicKey, validatedAt, statusFreshUntil,
                p256, digitalSignature, keyAgreement, clientAuth);
        result = 31 * result + Arrays.hashCode(certificatePolicyDigest);
        return result;
    }

    /**
     * 非敏感描述（FW-SEC-DSN-CR-017 §4 约束）：
     * 只输出 Profile、布尔能力位、验证时刻与摘要长度，不展开 DER / 公钥 / 摘要 / serial / 身份。
     */
    @Override
    public String toString() {
        return "ValidatedTboxDeviceCertificate{profile=" + profile
                + ", p256=" + p256
                + ", digitalSignature=" + digitalSignature
                + ", keyAgreement=" + keyAgreement
                + ", clientAuth=" + clientAuth
                + ", certificatePolicyDigest=" + digestLength()
                + ", validatedAt=" + validatedAt
                + ", statusFreshUntil=" + statusFreshUntil + '}';
    }

    private String digestLength() {
        return certificatePolicyDigest == null
                ? "null" : "[" + certificatePolicyDigest.length + " bytes]";
    }
}
