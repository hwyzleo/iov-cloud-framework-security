package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertPem;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusProtocolException;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 证书目录解析器（FW-SEC-DSN-CR-010 §3/§8，决策 RD-010-7）
 * <p>
 * 解析优先级（用户确认口径）：
 * <ol>
 *   <li>调用方携带的本次 mTLS 叶子证书（{@link PkiClient.CertificateStatusQuery#leafCertificateDer}）——
 *       step-ca 等无 serial 目录查询能力的 Provider 必须提供，保证校验的是本次实际使用证书；</li>
 *   <li>Provider 已定义的 {@link PkiClient#queryCertificate(String)}（legacy-rest 等具备证书查询能力时）；</li>
 *   <li>未来正式的证书目录 SPI（本 CR 不实现，不猜测未定义的 URL 协议）。</li>
 * </ol>
 * issuer 证书从受控 issuer 配置 / 证书链解析；OCSP/CRL 端点优先显式受控覆盖，其次叶子证书 AIA/CDP。
 * <p>
 * 安全约束：叶子证书为敏感材料，不持久化、不写日志；日志仅输出不可逆摘要。
 */
public class CertificateDirectoryResolver {

    private static final Logger log = LoggerFactory.getLogger(CertificateDirectoryResolver.class);

    private final ObjectProvider<PkiClient> pkiClientProvider;
    private final PkiRevocationProperties properties;
    private final CryptoProperties cryptoProperties;

    public CertificateDirectoryResolver(ObjectProvider<PkiClient> pkiClientProvider,
                                        PkiRevocationProperties properties,
                                        CryptoProperties cryptoProperties) {
        this.pkiClientProvider = Objects.requireNonNull(pkiClientProvider, "pkiClientProvider must not be null");
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.cryptoProperties = Objects.requireNonNull(cryptoProperties, "cryptoProperties must not be null");
    }

    /**
     * 解析证书状态查询上下文。
     *
     * @param query 查询输入
     * @return 叶子/issuer/端点上下文
     */
    public CertificateStatusContext resolve(PkiClient.CertificateStatusQuery query) {
        Objects.requireNonNull(query, "query must not be null");

        ResolvedCertificate resolved = resolveLeaf(query);
        X509Certificate issuer = resolveIssuer(resolved.leaf(), resolved.chain());

        URI ocspUri = firstNonBlankUri(properties.getOcsp().getUrl(), extractAiaOcspUrl(resolved.leaf()));
        URI crlUri = firstNonBlankUri(properties.getCrl().getUrl(), extractCdpUrl(resolved.leaf()));

        return new CertificateStatusContext(resolved.leaf(), issuer, ocspUri, crlUri, provider());
    }

    private String provider() {
        String configured = cryptoProperties.getPki().getProvider();
        if (configured == null || configured.isBlank()) {
            return "legacy-rest";
        }
        return configured.trim().toLowerCase();
    }

    private ResolvedCertificate resolveLeaf(PkiClient.CertificateStatusQuery query) {
        byte[] leafDer = query.leafCertificateDer();
        if (leafDer != null && leafDer.length > 0) {
            X509Certificate leaf = parseDer(leafDer);
            verifyLeafIdentity(leaf, query);
            return new ResolvedCertificate(leaf, List.of());
        }

        PkiClient pkiClient = pkiClientProvider.getIfAvailable();
        if (pkiClient == null) {
            throw new CertificateStatusConfigurationException(
                    "No PkiClient available to resolve certificate directory for serial-bearing query; "
                            + "provide leafCertificateDer (FW-SEC-DSN-CR-010 §3.3)");
        }
        PkiClient.CertificateResponse response;
        try {
            response = pkiClient.queryCertificate(query.serial());
        } catch (CertificateStatusConfigurationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new CertificateStatusConfigurationException(
                    "Provider does not expose a serial certificate directory and no leafCertificateDer was provided; "
                            + "provide the leaf certificate used for mTLS (FW-SEC-DSN-CR-010 §3.3)", e);
        }
        if (response == null || response.leafCertificate() == null || response.leafCertificate().length == 0) {
            throw new CertificateStatusProtocolException(
                    "Certificate directory returned no leaf certificate for the requested serial");
        }
        X509Certificate leaf = parseDer(response.leafCertificate());
        verifyLeafIdentity(leaf, query);
        return new ResolvedCertificate(leaf, parseChain(response.certificateChain()));
    }

    private void verifyLeafIdentity(X509Certificate leaf, PkiClient.CertificateStatusQuery query) {
        String actualSerial = RevocationDigest.canonicalSerial(leaf.getSerialNumber());
        if (!actualSerial.equals(query.serial())) {
            throw new CertificateStatusProtocolException(
                    "Resolved certificate serial does not match requested serial");
        }
        String normalizedFingerprint = query.sha256Fingerprint();
        if (normalizedFingerprint != null) {
            String actualFingerprint;
            try {
                actualFingerprint = RevocationDigest.sha256Hex(leaf.getEncoded());
            } catch (java.security.cert.CertificateEncodingException e) {
                throw new CertificateStatusProtocolException("Failed to encode resolved certificate", e);
            }
            if (!actualFingerprint.equalsIgnoreCase(normalizedFingerprint)) {
                throw new CertificateStatusProtocolException(
                        "Resolved certificate fingerprint does not match requested fingerprint");
            }
        }
        if (!leaf.getNotAfter().after(leaf.getNotBefore())) {
            throw new CertificateStatusProtocolException("Resolved certificate has an invalid validity period");
        }
    }

    private X509Certificate resolveIssuer(X509Certificate leaf, List<byte[]> chain) {
        // 叶子自签名：以自身作为 issuer（OCSP/CRL 校验用）
        if (leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
            try {
                leaf.verify(leaf.getPublicKey());
                return leaf;
            } catch (Exception e) {
                throw new CertificateStatusProtocolException("Self-issued leaf certificate signature is invalid", e);
            }
        }

        List<X509Certificate> candidates = new ArrayList<>(parseConfiguredIssuers());
        for (byte[] der : chain) {
            candidates.add(parseDer(der));
        }
        for (X509Certificate candidate : candidates) {
            if (!candidate.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
                continue;
            }
            try {
                leaf.verify(candidate.getPublicKey());
            } catch (Exception e) {
                continue;
            }
            if (candidate.getBasicConstraints() < 0) {
                throw new CertificateStatusProtocolException(
                        "Resolved issuer certificate is not a CA certificate");
            }
            return candidate;
        }

        if (candidates.isEmpty()) {
            throw new CertificateStatusConfigurationException(
                    "Cannot resolve issuer certificate: provide crypto.pki.revocation.issuer-cert-pem or a "
                            + "certificate chain alongside leafCertificateDer (FW-SEC-DSN-CR-010 §3.3)");
        }
        throw new CertificateStatusProtocolException(
                "Configured/chain issuer does not match the leaf certificate issuer");
    }

    private List<X509Certificate> parseConfiguredIssuers() {
        String pem = properties.getIssuerCertPem();
        if (pem == null || pem.isBlank()) {
            return List.of();
        }
        List<X509Certificate> issuers = new ArrayList<>();
        for (byte[] der : CertPem.parsePemBundle(pem)) {
            issuers.add(parseDer(der));
        }
        return issuers;
    }

    private static List<byte[]> parseChain(byte[] certificateChain) {
        if (certificateChain == null || certificateChain.length == 0) {
            return List.of();
        }
        try {
            return new net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateChainValidator()
                    .parseCertificateChain(certificateChain);
        } catch (RuntimeException e) {
            throw new CertificateStatusProtocolException(
                    "Certificate directory returned an unparseable certificate chain", e);
        }
    }

    private static X509Certificate parseDer(byte[] der) {
        try {
            return CertPem.parseCertificate(der);
        } catch (RuntimeException e) {
            throw new CertificateStatusProtocolException("Failed to parse certificate DER", e);
        }
    }

    private static URI firstNonBlankUri(String configured, URI fromCertificate) {
        if (configured != null && !configured.isBlank()) {
            return URI.create(configured.trim());
        }
        return fromCertificate;
    }

    private static URI extractAiaOcspUrl(X509Certificate leaf) {
        byte[] extension = leaf.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extension == null) {
            return null;
        }
        try {
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(
                    JcaX509ExtensionUtils.parseExtensionValue(extension));
            for (AccessDescription description : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_ocsp.equals(description.getAccessMethod())) {
                    GeneralName location = description.getAccessLocation();
                    if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        return URI.create(location.getName().toString());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("解析证书 AIA 失败，按无 OCSP 端点处理: {}", e.getMessage());
        }
        return null;
    }

    private static URI extractCdpUrl(X509Certificate leaf) {
        byte[] extension = leaf.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extension == null) {
            return null;
        }
        try {
            CRLDistPoint distPoint = CRLDistPoint.getInstance(
                    JcaX509ExtensionUtils.parseExtensionValue(extension));
            for (DistributionPoint point : distPoint.getDistributionPoints()) {
                DistributionPointName name = point.getDistributionPoint();
                if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                    continue;
                }
                GeneralNames names = GeneralNames.getInstance(name.getName());
                for (GeneralName generalName : names.getNames()) {
                    if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        return URI.create(generalName.getName().toString());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("解析证书 CDP 失败，按无 CRL 端点处理: {}", e.getMessage());
        }
        return null;
    }

    /**
     * 叶子证书与解析出的证书链。
     */
    private record ResolvedCertificate(X509Certificate leaf, List<byte[]> chain) {
    }
}
