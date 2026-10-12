package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;

import java.util.Objects;

/**
 * 证书状态查询可选门面（FW-SEC-DSN-CR-010 §8）
 * <p>
 * 薄封装，委托 {@link PkiClient#checkCertificateStatus(PkiClient.CertificateStatusQuery)}，
 * 便于业务侧在不直接依赖 PkiClient 时使用统一入口。不缓存结果，不改变实时查询语义。
 */
public class CertificateStatusTemplate {

    private final PkiClient pkiClient;

    public CertificateStatusTemplate(PkiClient pkiClient) {
        this.pkiClient = Objects.requireNonNull(pkiClient, "pkiClient must not be null");
    }

    /**
     * 查询证书状态。
     *
     * @param query 查询输入
     * @return 统一状态结果
     */
    public PkiClient.CertificateStatusResult checkCertificateStatus(
            PkiClient.CertificateStatusQuery query) {
        return pkiClient.checkCertificateStatus(query);
    }
}
