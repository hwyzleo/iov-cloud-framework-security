package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import java.net.URI;
import java.security.cert.X509Certificate;

/**
 * 证书状态查询上下文（FW-SEC-DSN-CR-010 §3/§8）
 * <p>
 * 由 {@link CertificateDirectoryResolver} 解析得到：待查叶子证书、用于校验 OCSP/CRL 的 issuer 证书，
 * 以及由证书 AIA/CDP 或显式受控覆盖得到的 responder/CDP 端点。
 * <p>
 * issuer 证书用于 OCSP CertID 的 name/key hash 与响应签名校验，以及 CRL 签名与 issuer 校验。
 *
 * @param leafCertificate   叶子证书（framework 内部使用，不持久化、不写日志）
 * @param issuerCertificate 叶子签发者证书
 * @param ocspUri           OCSP responder 端点（可为空，表示无可用 AIA/覆盖）
 * @param crlUri            CRL 分发点（可为空）
 * @param provider          签发 Provider（step-ca / legacy-rest），仅用于指标 label
 */
public record CertificateStatusContext(
        X509Certificate leafCertificate,
        X509Certificate issuerCertificate,
        URI ocspUri,
        URI crlUri,
        String provider) {
}
