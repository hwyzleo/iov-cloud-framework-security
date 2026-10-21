package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

import java.util.Objects;

/**
 * 信封构建上下文（FW-SEC-DSN-CR-019 §5.3/§6）。
 * <p>
 * 全部为<strong>非敏感</strong>字段（不含 VIN 原文、派生材料与 Wrapped Key）；
 * 逻辑引用只允许含锚摘要。
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
        String recipientCertificateFingerprint) {

    public WrapEnvelopeContext {
        Objects.requireNonNull(logicalKeyId, "logicalKeyId must not be null");
        Objects.requireNonNull(businessDomain, "businessDomain must not be null");
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        Objects.requireNonNull(operationId, "operationId must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(recipientCertificateFingerprint,
                "recipientCertificateFingerprint must not be null");
    }
}
