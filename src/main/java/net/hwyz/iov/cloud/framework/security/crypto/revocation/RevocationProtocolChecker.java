package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;

import java.time.Instant;

/**
 * 具体吊销协议检查器（OCSP / CRL，FW-SEC-DSN-CR-010 §3）
 * <p>
 * 由 {@link DefaultCertificateStatusChecker} 按受治理模式编排；所有协议尝试与重试共享
 * {@code deadline}（单次 total budget）。
 */
public interface RevocationProtocolChecker {

    /**
     * @return 本检查器对应的来源
     */
    PkiClient.RevocationSource source();

    /**
     * 执行一次协议查询。
     *
     * @param context    证书/issuer/端点上下文
     * @param decisionAt 裁决时刻
     * @param deadline   总预算截止时刻（含重试）
     * @return 统一状态结果
     */
    PkiClient.CertificateStatusResult check(CertificateStatusContext context, Instant decisionAt, Instant deadline);
}
