package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;

/**
 * 证书状态检查器 SPI（FW-SEC-DSN-CR-010 §8）
 * <p>
 * 由 {@code DefaultCertificateStatusChecker} 实现并注入 provider 的
 * {@link PkiClient#checkCertificateStatus(PkiClient.CertificateStatusQuery)}。
 * 关闭（{@code crypto.pki.revocation.enabled=false}）时不注册本 Bean，provider 保持默认
 * configuration-disabled 行为。
 */
public interface CertificateStatusChecker {

    /**
     * 执行一次证书状态查询（OCSP 优先 / CRL 后备，受治理模式与总预算约束）。
     *
     * @param query 查询输入
     * @return 统一状态结果；UNKNOWN 为一等状态，绝不返回 GOOD 作为兜底
     */
    PkiClient.CertificateStatusResult check(PkiClient.CertificateStatusQuery query);
}
