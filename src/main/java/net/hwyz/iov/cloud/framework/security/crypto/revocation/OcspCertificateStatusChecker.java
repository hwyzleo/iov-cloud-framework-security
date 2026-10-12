package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusProtocolException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusTrustValidationException;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

/**
 * 标准 OCSP 检查器（FW-SEC-DSN-CR-010 §3.1）
 * <p>
 * HTTP POST DER；校验响应状态、签名链/授权 responder、issuer name hash/key hash、serial、
 * producedAt、thisUpdate、nextUpdate 与允许时钟偏差、nonce 策略。OCSP 明确 REVOKED 不再查询 CRL。
 */
public class OcspCertificateStatusChecker implements RevocationProtocolChecker {

    private static final Logger log = LoggerFactory.getLogger(OcspCertificateStatusChecker.class);

    private static final String CONTENT_TYPE_OCSP_REQUEST = "application/ocsp-request";
    private static final String ACCEPT_OCSP_RESPONSE = "application/ocsp-response";
    private static final String EKU_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    private final RevocationHttpTransport transport;
    private final RevocationRequestExecutor executor;
    private final PkiRevocationProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    public OcspCertificateStatusChecker(RevocationHttpTransport transport,
                                        PkiRevocationProperties properties,
                                        PkiRevocationMetrics metrics,
                                        Duration defaultReadTimeout) {
        this.transport = transport;
        this.properties = properties;
        this.executor = new RevocationRequestExecutor(transport, properties, metrics, defaultReadTimeout);
    }

    @Override
    public PkiClient.RevocationSource source() {
        return PkiClient.RevocationSource.OCSP;
    }

    @Override
    public PkiClient.CertificateStatusResult check(CertificateStatusContext context,
                                                   Instant decisionAt,
                                                   Instant deadline) {
        X509Certificate leaf = context.leafCertificate();
        X509Certificate issuer = context.issuerCertificate();
        URI uri = context.ocspUri();
        if (uri == null) {
            throw new CertificateStatusConfigurationException(
                    "No OCSP responder available (certificate AIA missing and no crypto.pki.revocation.ocsp.url)");
        }

        String noncePolicy = properties.getOcsp().normalizedNoncePolicy();
        byte[] nonce = "disabled".equals(noncePolicy) ? null : randomNonce();
        byte[] requestDer = buildRequest(issuer, leaf.getSerialNumber(), nonce);

        RevocationHttpTransport.Response response = executor.execute(
                timeout -> transport.post(uri, requestDer, CONTENT_TYPE_OCSP_REQUEST, ACCEPT_OCSP_RESPONSE, timeout),
                deadline);

        byte[] body = response.body();
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw mapHttpError(response.statusCode());
        }
        if (body == null || body.length == 0) {
            throw new CertificateStatusProtocolException("OCSP responder returned an empty body");
        }
        return parseResponse(body, issuer, leaf, decisionAt, nonce, noncePolicy);
    }

    private byte[] buildRequest(X509Certificate issuer, java.math.BigInteger serial, byte[] nonce) {
        try {
            DigestCalculator digest = new JcaDigestCalculatorProviderBuilder().build()
                    .get(CertificateID.HASH_SHA1);
            CertificateID certificateId = new JcaCertificateID(digest, issuer, serial);
            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(certificateId);
            if (nonce != null) {
                org.bouncycastle.asn1.x509.ExtensionsGenerator extensions =
                        new org.bouncycastle.asn1.x509.ExtensionsGenerator();
                extensions.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                        new DEROctetString(nonce));
                builder.setRequestExtensions(extensions.generate());
            }
            OCSPReq request = builder.build();
            return request.getEncoded();
        } catch (Exception e) {
            throw new CertificateStatusConfigurationException("Failed to build OCSP request", e);
        }
    }

    private PkiClient.CertificateStatusResult parseResponse(byte[] body,
                                                           X509Certificate issuer,
                                                           X509Certificate leaf,
                                                           Instant decisionAt,
                                                           byte[] nonce,
                                                           String noncePolicy) {
        OCSPResp ocspResp;
        try {
            ocspResp = new OCSPResp(body);
        } catch (Exception e) {
            throw new CertificateStatusProtocolException("Failed to parse OCSP response", e);
        }
        if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
            throw mapOcspStatus(ocspResp.getStatus());
        }

        BasicOCSPResp basic;
        try {
            Object responseObject = ocspResp.getResponseObject();
            if (!(responseObject instanceof BasicOCSPResp basicResp)) {
                throw new CertificateStatusProtocolException(
                        "OCSP successful response does not contain a BasicOCSPResp");
            }
            basic = basicResp;
        } catch (CertificateStatusProtocolException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateStatusProtocolException("Failed to read OCSP response object", e);
        }

        verifySignature(basic, issuer);
        verifyNonce(basic, nonce, noncePolicy);

        SingleResp single = selectSingleResponse(basic, issuer, leaf.getSerialNumber());
        validateTimes(basic, single, decisionAt);

        Instant thisUpdate = single.getThisUpdate().toInstant();
        Instant nextUpdate = single.getNextUpdate() != null ? single.getNextUpdate().toInstant() : null;
        PkiClient.RevocationState state = mapCertificateStatus(single.getCertStatus());

        log.debug("OCSP 查询完成: outcome={}, thisUpdate={}, nextUpdate={}", state, thisUpdate, nextUpdate);
        return new PkiClient.CertificateStatusResult(state,
                leaf.getNotBefore().toInstant(), leaf.getNotAfter().toInstant(),
                thisUpdate, nextUpdate, PkiClient.RevocationSource.OCSP, Instant.now());
    }

    private void verifySignature(BasicOCSPResp basic, X509Certificate issuer) {
        try {
            PublicKey verificationKey = resolveResponderKey(basic, issuer);
            boolean valid = basic.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().build(verificationKey));
            if (!valid) {
                throw new CertificateStatusTrustValidationException(
                        "OCSP response signature verification failed");
            }
        } catch (CertificateStatusTrustValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateStatusTrustValidationException("OCSP response signature validation error", e);
        }
    }

    /**
     * 解析响应签名密钥：优先由 issuer 直签/授权，否则使用响应内受 issuer 签发的 delegated responder 证书。
     */
    private PublicKey resolveResponderKey(BasicOCSPResp basic, X509Certificate issuer) {
        ResponderID responderId = basic.getResponderId().toASN1Primitive();
        byte[] keyHash = responderId.getKeyHash();
        org.bouncycastle.asn1.x500.X500Name name = responderId.getName();

        // 1) responder 即 issuer
        if (name != null && name.equals(issuerSubjectName(issuer))) {
            return issuer.getPublicKey();
        }
        if (keyHash != null && Arrays.equals(keyHash, issuerKeyHash(issuer))) {
            return issuer.getPublicKey();
        }

        // 2) 响应内 delegated responder 证书
        X509CertificateHolder[] certs = basic.getCerts();
        if (certs != null) {
            for (X509CertificateHolder holder : certs) {
                if (!isAuthorizedResponder(holder, responderId, keyHash)) {
                    continue;
                }
                X509Certificate responderCert = toCertificate(holder);
                validateDelegatedResponder(responderCert, issuer);
                return responderCert.getPublicKey();
            }
        }
        throw new CertificateStatusTrustValidationException(
                "OCSP responder is not authorized: no responder ID match and no delegated OCSP signing certificate");
    }

    private boolean isAuthorizedResponder(X509CertificateHolder holder, ResponderID responderId, byte[] keyHash) {
        if (keyHash != null) {
            byte[] candidate = responderKeyHash(holder);
            return candidate != null && Arrays.equals(candidate, keyHash);
        }
        if (responderId.getName() != null) {
            return responderId.getName().equals(holder.getSubject());
        }
        return false;
    }

    private void validateDelegatedResponder(X509Certificate responderCert, X509Certificate issuer) {
        try {
            if (!responderCert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                throw new CertificateStatusTrustValidationException(
                        "Delegated OCSP responder certificate is not issued by the certificate issuer");
            }
            responderCert.verify(issuer.getPublicKey());
            responderCert.checkValidity();
            java.util.List<String> eku = responderCert.getExtendedKeyUsage();
            if (eku == null || !eku.contains(EKU_OCSP_SIGNING)) {
                throw new CertificateStatusTrustValidationException(
                        "Delegated OCSP responder certificate is missing id-kp-OCSPSigning EKU");
            }
        } catch (CertificateStatusTrustValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateStatusTrustValidationException(
                    "Delegated OCSP responder certificate validation failed", e);
        }
    }

    private void verifyNonce(BasicOCSPResp basic, byte[] nonce, String noncePolicy) {
        if (nonce == null) {
            return; // disabled policy: 客户端不发送 nonce，也不做比对
        }
        Extension extension = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (extension == null) {
            if ("required".equals(noncePolicy)) {
                throw new CertificateStatusProtocolException(
                        "OCSP responder did not return a nonce while policy=required; "
                                + "client must not silently downgrade");
            }
            return;
        }
        byte[] echoed = DEROctetString.getInstance(extension.getExtnValue().getOctets()).getOctets();
        if (!Arrays.equals(nonce, echoed)) {
            throw new CertificateStatusProtocolException("OCSP response nonce mismatch");
        }
    }

    private SingleResp selectSingleResponse(BasicOCSPResp basic, X509Certificate issuer, java.math.BigInteger serial) {
        try {
            org.bouncycastle.operator.DigestCalculatorProvider digestProvider =
                    new JcaDigestCalculatorProviderBuilder().build();
            X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
            for (SingleResp single : basic.getResponses()) {
                CertificateID certificateID = single.getCertID();
                if (!certificateID.getSerialNumber().equals(serial)) {
                    continue;
                }
                if (certificateID.matchesIssuer(issuerHolder, digestProvider)) {
                    return single;
                }
            }
        } catch (Exception e) {
            throw new CertificateStatusProtocolException("Failed to match OCSP response entry to issuer/serial", e);
        }
        throw new CertificateStatusProtocolException(
                "OCSP response does not contain an entry matching the requested issuer/serial");
    }

    private void validateTimes(BasicOCSPResp basic, SingleResp single, Instant decisionAt) {
        Duration skew = properties.getClockSkew() != null ? properties.getClockSkew() : Duration.ofSeconds(30);
        Instant producedAt = basic.getProducedAt().toInstant();
        if (producedAt.isAfter(decisionAt.plus(skew))) {
            throw new CertificateStatusProtocolException("OCSP producedAt is in the future beyond allowed clock skew");
        }
        Instant thisUpdate = single.getThisUpdate().toInstant();
        if (thisUpdate.isAfter(decisionAt.plus(skew))) {
            throw new CertificateStatusProtocolException("OCSP thisUpdate is in the future beyond allowed clock skew");
        }
        if (single.getNextUpdate() != null) {
            Instant nextUpdate = single.getNextUpdate().toInstant();
            if (decisionAt.isAfter(nextUpdate.plus(skew))) {
                throw new CertificateStatusProtocolException("OCSP response is stale: nextUpdate has passed");
            }
        }
    }

    private static PkiClient.RevocationState mapCertificateStatus(CertificateStatus status) {
        if (status == null) {
            return PkiClient.RevocationState.GOOD;
        }
        if (status instanceof RevokedStatus) {
            return PkiClient.RevocationState.REVOKED;
        }
        if (status instanceof UnknownStatus) {
            return PkiClient.RevocationState.UNKNOWN;
        }
        return PkiClient.RevocationState.UNKNOWN;
    }

    private RuntimeException mapOcspStatus(int status) {
        return switch (status) {
            case OCSPResp.TRY_LATER -> new CertificateStatusDependencyUnavailableException(
                    "OCSP responder replied tryLater (temporarily unable to determine status)");
            case OCSPResp.UNAUTHORIZED -> new CertificateStatusConfigurationException(
                    "OCSP responder rejected the request as unauthorized");
            case OCSPResp.MALFORMED_REQUEST -> new CertificateStatusProtocolException(
                    "OCSP responder rejected the request as malformed");
            case OCSPResp.SIG_REQUIRED -> new CertificateStatusConfigurationException(
                    "OCSP responder requires a signed request (not configured)");
            default -> new CertificateStatusProtocolException(
                    "OCSP responder returned non-successful status: " + status);
        };
    }

    private RuntimeException mapHttpError(int statusCode) {
        if (statusCode == 429) {
            return new CertificateStatusDependencyUnavailableException(
                    "OCSP responder rate limited the request (HTTP 429)");
        }
        if (statusCode >= 400 && statusCode < 500) {
            if (statusCode == 401 || statusCode == 403) {
                return new CertificateStatusConfigurationException(
                        "OCSP responder rejected authentication/authorization (HTTP " + statusCode + ")");
            }
            return new CertificateStatusProtocolException(
                    "OCSP responder returned client error HTTP " + statusCode);
        }
        return new CertificateStatusDependencyUnavailableException(
                "OCSP responder unavailable (HTTP " + statusCode + ")");
    }

    private byte[] randomNonce() {
        byte[] nonce = new byte[16];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    private static org.bouncycastle.asn1.x500.X500Name issuerSubjectName(X509Certificate issuer) {
        try {
            return new JcaX509CertificateHolder(issuer).getSubject();
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new CertificateStatusTrustValidationException("Failed to encode issuer certificate", e);
        }
    }

    /**
     * issuer 的 responder key hash：SHA-1(SubjectPublicKeyInfo.publicKeyData)。
     */
    private static byte[] issuerKeyHash(X509Certificate issuer) {
        try {
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                    org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(issuer.getPublicKey().getEncoded());
            return sha1(spki.getPublicKeyData().getBytes());
        } catch (Exception e) {
            throw new CertificateStatusTrustValidationException("Failed to compute issuer key hash", e);
        }
    }

    private static byte[] responderKeyHash(X509CertificateHolder holder) {
        try {
            return sha1(holder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] sha1(byte[] data) throws java.security.NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    private static X509Certificate toCertificate(X509CertificateHolder holder) {
        try {
            return new JcaX509CertificateConverter().getCertificate(holder);
        } catch (Exception e) {
            throw new CertificateStatusTrustValidationException("Failed to convert responder certificate", e);
        }
    }
}
