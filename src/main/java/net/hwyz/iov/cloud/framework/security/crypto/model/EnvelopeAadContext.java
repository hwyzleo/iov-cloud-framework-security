package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * 信封 AAD 编码上下文（FW-SEC-DSN-CR-020 §2）。
 * <p>
 * 协议无关的 {@link EnvelopeAadEncoder} 输入：承载 AES-256-GCM 附加认证数据的
 * <strong>非敏感</strong>上下文（信封格式版本、封装套件、请求标识、业务域、用途、
 * 逻辑密钥标识、业务版本、根版本、派生版本与收方证书摘要）。
 * <p>
 * {@code recipientCertificateDigest} 为收方证书 SHA-256 摘要（32 字节），由
 * framework 从已验证收方证据的指纹（小写十六进制）还原；不含 VIN 原文与任何秘密材料。
 * <p>
 * 所有 {@code byte[]} 组件构造与访问均防御性复制；非法长度 fail-closed。
 *
 * @param formatVersion            信封格式版本（首期 {@code 1}）
 * @param wrappingSuite            封装套件（首期 ECDH-ES P-256）
 * @param requestId                证书 enrollment 请求标识（可空）
 * @param businessDomain           业务域（首期 = bizType.name()）
 * @param purpose                  派生用途
 * @param logicalKeyId             逻辑派生实例标识（确定性、非敏感）
 * @param businessKeyVersion       VMD 业务版本
 * @param rootKeyVersion           Transit/HSM 根版本（选定）
 * @param derivationVersion        派生格式版本
 * @param recipientCertificateDigest 收方证书 SHA-256 摘要（32 字节）
 */
public record EnvelopeAadContext(
        int formatVersion,
        WrappingSuite wrappingSuite,
        String requestId,
        String businessDomain,
        KeyPurpose purpose,
        String logicalKeyId,
        long businessKeyVersion,
        long rootKeyVersion,
        String derivationVersion,
        byte[] recipientCertificateDigest) {

    /** 收方证书摘要固定长度（SHA-256）。 */
    public static final int RECIPIENT_CERTIFICATE_DIGEST_LENGTH = 32;

    public EnvelopeAadContext {
        Objects.requireNonNull(wrappingSuite, "wrappingSuite must not be null");
        Objects.requireNonNull(businessDomain, "businessDomain must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(logicalKeyId, "logicalKeyId must not be null");
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        if (formatVersion < 1) {
            throw new IllegalArgumentException("formatVersion must be >= 1: " + formatVersion);
        }
        if (businessKeyVersion < 0) {
            throw new IllegalArgumentException("businessKeyVersion must not be negative");
        }
        if (rootKeyVersion < 0) {
            throw new IllegalArgumentException("rootKeyVersion must not be negative");
        }
        if (recipientCertificateDigest == null
                || recipientCertificateDigest.length != RECIPIENT_CERTIFICATE_DIGEST_LENGTH) {
            throw new IllegalArgumentException(
                    "recipientCertificateDigest must be exactly " + RECIPIENT_CERTIFICATE_DIGEST_LENGTH
                            + " bytes, got " + (recipientCertificateDigest == null
                            ? "null" : recipientCertificateDigest.length + " bytes"));
        }
        recipientCertificateDigest = recipientCertificateDigest.clone();
    }

    @Override
    public byte[] recipientCertificateDigest() {
        return recipientCertificateDigest.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof EnvelopeAadContext that)) {
            return false;
        }
        return formatVersion == that.formatVersion
                && businessKeyVersion == that.businessKeyVersion
                && rootKeyVersion == that.rootKeyVersion
                && wrappingSuite == that.wrappingSuite
                && purpose == that.purpose
                && Objects.equals(requestId, that.requestId)
                && Objects.equals(businessDomain, that.businessDomain)
                && Objects.equals(logicalKeyId, that.logicalKeyId)
                && Objects.equals(derivationVersion, that.derivationVersion)
                && Arrays.equals(recipientCertificateDigest, that.recipientCertificateDigest);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(formatVersion, wrappingSuite, requestId, businessDomain, purpose,
                logicalKeyId, businessKeyVersion, rootKeyVersion, derivationVersion);
        result = 31 * result + Arrays.hashCode(recipientCertificateDigest);
        return result;
    }

    /**
     * 非敏感描述：只输出版本/套件/元数据与 bytes 长度，不展开摘要内容。
     */
    @Override
    public String toString() {
        return "EnvelopeAadContext{formatVersion=" + formatVersion
                + ", wrappingSuite=" + wrappingSuite
                + ", requestId='" + requestId + "'"
                + ", businessDomain='" + businessDomain + "'"
                + ", purpose=" + purpose
                + ", logicalKeyId='" + logicalKeyId + "'"
                + ", businessKeyVersion=" + businessKeyVersion
                + ", rootKeyVersion=" + rootKeyVersion
                + ", derivationVersion='" + derivationVersion + "'"
                + ", recipientCertificateDigest=" + (recipientCertificateDigest == null
                ? "null" : "[" + recipientCertificateDigest.length + " bytes]") + '}';
    }
}
