package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

import java.util.Objects;

/**
 * 信封构建上下文（FW-SEC-DSN-CR-019 §5.3/§6；FW-SEC-DSN-CR-020 §2）。
 * <p>
 * 全部为<strong>非敏感</strong>字段（不含 VIN 原文、派生材料与 Wrapped Key）；
 * 逻辑引用只允许含锚摘要。
 * <p>
 * {@code aadProfileId}（CR-020）：新 V2C ECDH-ES keyprov 必须非空（外部 AAD profile）；
 * {@code null} 仅表示无 profile 的旧格式/legacy core AAD 路径（只允许原格式对账/终结）。
 *
 * @param requestId                    证书 enrollment 请求标识（可空）
 * @param businessDomain               业务域（首期 = bizType.name()）
 * @param logicalKeyId                 逻辑派生实例标识（确定性、非敏感）
 * @param businessKeyVersion           VMD 业务版本
 * @param rootKeyVersion               Transit 根版本
 * @param derivationVersion            派生版本
 * @param operationId                  操作标识（对账主键）
 * @param purpose                      派生用途
 * @param recipientCertificateFingerprint 收方证书 SHA-256 指纹（小写十六进制）
 * @param aadProfileId                 使用的 AAD profile 标识（CR-020；null = legacy 无 profile）
 */
public record WrapEnvelopeContext(
        String requestId,
        String businessDomain,
        String logicalKeyId,
        long businessKeyVersion,
        long rootKeyVersion,
        String derivationVersion,
        String operationId,
        KeyPurpose purpose,
        String recipientCertificateFingerprint,
        String aadProfileId) {

    public WrapEnvelopeContext {
        Objects.requireNonNull(logicalKeyId, "logicalKeyId must not be null");
        Objects.requireNonNull(businessDomain, "businessDomain must not be null");
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        Objects.requireNonNull(operationId, "operationId must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(recipientCertificateFingerprint,
                "recipientCertificateFingerprint must not be null");
        if (aadProfileId != null && aadProfileId.isBlank()) {
            throw new IllegalArgumentException("aadProfileId must not be blank when present");
        }
    }

    /**
     * 兼容构造（CR-020 additive）：不携带 aadProfileId 的旧格式上下文（{@code null}）。
     */
    public WrapEnvelopeContext(
            String requestId,
            String businessDomain,
            String logicalKeyId,
            long businessKeyVersion,
            long rootKeyVersion,
            String derivationVersion,
            String operationId,
            KeyPurpose purpose,
            String recipientCertificateFingerprint) {
        this(requestId, businessDomain, logicalKeyId, businessKeyVersion, rootKeyVersion,
                derivationVersion, operationId, purpose, recipientCertificateFingerprint, null);
    }
}
