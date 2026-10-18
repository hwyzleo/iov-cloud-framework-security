package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Objects;

/**
 * Envelope AAD v1（FW-SEC-DSN-CR-014 §3.3）。
 * <p>
 * AES-256-GCM 附加认证数据（AAD）的<strong>逻辑字段集</strong>，绑定非敏感上下文：
 * 协议版本、套件、请求标识、业务域、用途、密钥标识、业务版本、根版本、派生版本与收方证书指纹。
 * <p>
 * canonical 二进制编码由 {@code DerivedKeyEnvelopeCanonical#aadBytes} 提供：确定性字段顺序 +
 * 长度前缀编码。PAR-PROTO 后续 CR 负责 wire 映射，但<strong>不得改变密码学 canonical bytes</strong>。
 *
 * @param envelopeVersion                 信封版本（v1）
 * @param wrappingSuite                   封装套件
 * @param requestId                       请求标识
 * @param businessDomain                  业务域
 * @param purpose                         派生用途
 * @param keyId                           逻辑密钥标识
 * @param businessKeyVersion              VMD 业务版本
 * @param rootKeyVersion                  Transit/HSM 根版本
 * @param derivationVersion               派生格式版本
 * @param recipientCertificateFingerprint 收方证书 SHA-256 指纹（十六进制小写）
 */
public record EnvelopeAadV1(
        String envelopeVersion,
        WrappingSuite wrappingSuite,
        String requestId,
        String businessDomain,
        KeyPurpose purpose,
        String keyId,
        long businessKeyVersion,
        long rootKeyVersion,
        String derivationVersion,
        String recipientCertificateFingerprint) {

    public EnvelopeAadV1 {
        Objects.requireNonNull(envelopeVersion, "envelopeVersion must not be null");
        Objects.requireNonNull(wrappingSuite, "wrappingSuite must not be null");
    }
}
