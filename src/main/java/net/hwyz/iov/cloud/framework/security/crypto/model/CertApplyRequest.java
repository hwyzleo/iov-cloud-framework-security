package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Map;
import java.util.Objects;

/**
 * 证书申请请求
 *
 * @param certificateProfile 证书配置文件
 * @param pkcs10Csr          PKCS#10 CSR（DER 或 PEM 编码）
 * @param subject            主体引用
 * @param idempotencyKey     幂等键
 * @param context            上下文信息
 */
public record CertApplyRequest(

        CertificateProfile certificateProfile,

        byte[] pkcs10Csr,

        SubjectRef subject,

        String idempotencyKey,

        Map<String, String> context
) {

    public CertApplyRequest {
        Objects.requireNonNull(certificateProfile, "certificateProfile must not be null");
        Objects.requireNonNull(pkcs10Csr, "pkcs10Csr must not be null");
        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey must not be null");
    }
}
