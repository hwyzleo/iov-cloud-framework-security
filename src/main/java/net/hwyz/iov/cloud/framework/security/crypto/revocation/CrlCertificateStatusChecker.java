package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusProtocolException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusTrustValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

/**
 * 标准 CRL 检查器（FW-SEC-DSN-CR-010 §3.2）
 * <p>
 * HTTP GET DER/PEM；校验 CRL issuer、签名、thisUpdate、nextUpdate 与 serial。
 * 过期 CRL 视为「协议给出但不可用于结论」的一等 UNKNOWN（TSP-DSN-CR-011 §6），绝不返回 GOOD。
 */
public class CrlCertificateStatusChecker implements RevocationProtocolChecker {

    private static final Logger log = LoggerFactory.getLogger(CrlCertificateStatusChecker.class);

    private static final String ACCEPT_CRL = "application/pkix-crl, application/pkcs7-mime, */*";
    private static final String DELTA_CRL_OID = "2.5.29.27";

    private final RevocationHttpTransport transport;
    private final RevocationRequestExecutor executor;
    private final PkiRevocationProperties properties;

    public CrlCertificateStatusChecker(RevocationHttpTransport transport,
                                       PkiRevocationProperties properties,
                                       PkiRevocationMetrics metrics,
                                       Duration defaultReadTimeout) {
        this.transport = transport;
        this.properties = properties;
        this.executor = new RevocationRequestExecutor(transport, properties, metrics, defaultReadTimeout);
    }

    @Override
    public PkiClient.RevocationSource source() {
        return PkiClient.RevocationSource.CRL;
    }

    @Override
    public PkiClient.CertificateStatusResult check(CertificateStatusContext context,
                                                   Instant decisionAt,
                                                   Instant deadline) {
        X509Certificate leaf = context.leafCertificate();
        X509Certificate issuer = context.issuerCertificate();
        URI uri = context.crlUri();
        if (uri == null) {
            throw new CertificateStatusConfigurationException(
                    "No CRL distribution point available (certificate CDP missing and no "
                            + "crypto.pki.revocation.crl.url)");
        }

        RevocationHttpTransport.Response response = executor.execute(
                timeout -> transport.get(uri, timeout, ACCEPT_CRL), deadline);

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw mapHttpError(response.statusCode());
        }
        byte[] body = response.body();
        if (body == null || body.length == 0) {
            throw new CertificateStatusProtocolException("CRL distribution point returned an empty body");
        }

        X509CRL crl = parseCrl(body);
        if (crl.getExtensionValue(DELTA_CRL_OID) != null) {
            throw new CertificateStatusProtocolException(
                    "Delta CRL is not supported for determinate revocation status");
        }
        verifyCrl(crl, issuer);

        Instant thisUpdate = crl.getThisUpdate().toInstant();
        Instant nextUpdate = crl.getNextUpdate() != null ? crl.getNextUpdate().toInstant() : null;
        Duration skew = properties.getClockSkew() != null ? properties.getClockSkew() : Duration.ofSeconds(30);

        PkiClient.RevocationState state;
        if (nextUpdate != null && decisionAt.isAfter(nextUpdate.plus(skew))) {
            log.warn("CRL 已过期（nextUpdate 早于裁决时刻），返回 UNKNOWN");
            state = PkiClient.RevocationState.UNKNOWN;
        } else if (crl.getRevokedCertificate(leaf.getSerialNumber()) != null) {
            state = PkiClient.RevocationState.REVOKED;
        } else {
            state = PkiClient.RevocationState.GOOD;
        }

        log.debug("CRL 查询完成: outcome={}, thisUpdate={}, nextUpdate={}", state, thisUpdate, nextUpdate);
        return new PkiClient.CertificateStatusResult(state, context.subjectCommonName(),
                leaf.getNotBefore().toInstant(), leaf.getNotAfter().toInstant(),
                thisUpdate, nextUpdate, PkiClient.RevocationSource.CRL, Instant.now());
    }

    private X509CRL parseCrl(byte[] body) {
        try {
            java.security.cert.CertificateFactory factory =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            return (X509CRL) factory.generateCRL(new ByteArrayInputStream(body));
        } catch (Exception e) {
            throw new CertificateStatusProtocolException("Failed to parse CRL (DER/PEM)", e);
        }
    }

    private void verifyCrl(X509CRL crl, X509Certificate issuer) {
        try {
            if (!crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                throw new CertificateStatusTrustValidationException(
                        "CRL issuer does not match the certificate issuer");
            }
            crl.verify(issuer.getPublicKey());
        } catch (CertificateStatusTrustValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateStatusTrustValidationException("CRL signature verification failed", e);
        }
    }

    private RuntimeException mapHttpError(int statusCode) {
        if (statusCode == 429) {
            return new CertificateStatusDependencyUnavailableException(
                    "CRL distribution point rate limited the request (HTTP 429)");
        }
        if (statusCode >= 400 && statusCode < 500) {
            if (statusCode == 401 || statusCode == 403) {
                return new CertificateStatusConfigurationException(
                        "CRL distribution point rejected authentication/authorization (HTTP " + statusCode + ")");
            }
            return new CertificateStatusProtocolException(
                    "CRL distribution point returned client error HTTP " + statusCode);
        }
        return new CertificateStatusDependencyUnavailableException(
                "CRL distribution point unavailable (HTTP " + statusCode + ")");
    }
}
