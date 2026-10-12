package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.cert.ocsp.jcajce.JcaRespID;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

/**
 * 证书吊销查询测试材料生成（Root CA → Intermediate CA → Leaf / OCSP Responder / CRL）。
 * <p>
 * 叶子证书携带 AIA（OCSP URL）与 CDP（CRL URL）；OCSP 响应与 CRL 由 intermediate CA 签发。
 */
public final class TestRevocationMaterial {

    public static final X500Name ROOT_SUBJECT = new X500Name("CN=IOV Revocation Test Root CA");
    public static final X500Name ISSUER_SUBJECT = new X500Name("CN=IOV Revocation Test Issuer CA");
    public static final X500Name LEAF_SUBJECT = new X500Name("CN=revocation-leaf");
    public static final X500Name RESPONDER_SUBJECT = new X500Name("CN=IOV Revocation Test OCSP Responder");

    public static final BigInteger LEAF_SERIAL = new BigInteger("1234567890abcdef", 16);

    private TestRevocationMaterial() {
    }

    public enum ResponderMode {
        /**
         * 响应签名者为 issuer（responderID=issuer）
         */
        ISSUER,
        /**
         * 响应签名者为 delegated responder 证书（随响应下发）
         */
        DELEGATED,
        /**
         * responderID 声明为 issuer，但用非 issuer 私钥签名（坏签名）
         */
        BAD_SIGNATURE
    }

    public record Material(
            KeyPair rootKeyPair,
            X509Certificate rootCert,
            KeyPair issuerKeyPair,
            X509Certificate issuerCert,
            KeyPair leafKeyPair,
            X509Certificate leafCert,
            KeyPair responderKeyPair,
            X509Certificate responderCert) {

        public byte[] leafDer() throws Exception {
            return leafCert.getEncoded();
        }

        public byte[] rootPem() {
            try {
                return pem("CERTIFICATE", rootCert.getEncoded()).getBytes();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        public byte[] issuerPem() {
            try {
                return pem("CERTIFICATE", issuerCert.getEncoded()).getBytes();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    public static Material generate(String ocspUrl, String crlUrl) throws Exception {
        KeyPair rootKeyPair = generateKeyPair();
        X509Certificate rootCert = issueSelfSignedRoot(rootKeyPair);

        KeyPair issuerKeyPair = generateKeyPair();
        X509Certificate issuerCert = issueCa(ROOT_SUBJECT, rootKeyPair,
                ISSUER_SUBJECT, issuerKeyPair.getPublic(), BigInteger.valueOf(2));

        KeyPair leafKeyPair = generateKeyPair();
        X509Certificate leafCert = issueLeaf(ISSUER_SUBJECT, issuerKeyPair, leafKeyPair.getPublic(),
                LEAF_SERIAL, ocspUrl, crlUrl);

        KeyPair responderKeyPair = generateKeyPair();
        X509Certificate responderCert = issueResponder(ISSUER_SUBJECT, issuerKeyPair,
                responderKeyPair.getPublic());

        return new Material(rootKeyPair, rootCert, issuerKeyPair, issuerCert,
                leafKeyPair, leafCert, responderKeyPair, responderCert);
    }

    public static byte[] ocspResponse(Material material, CertificateStatus status,
                                      Date thisUpdate, Date nextUpdate, byte[] nonce,
                                      ResponderMode mode) throws Exception {
        return buildOcspResponse(material, material.leafCert().getSerialNumber(), status,
                thisUpdate, nextUpdate, nonce, mode);
    }

    public static byte[] ocspResponseForSerial(Material material, BigInteger serial, CertificateStatus status,
                                               Date thisUpdate, Date nextUpdate, byte[] nonce,
                                               ResponderMode mode) throws Exception {
        return buildOcspResponse(material, serial, status, thisUpdate, nextUpdate, nonce, mode);
    }

    private static byte[] buildOcspResponse(Material material, BigInteger serial, CertificateStatus status,
                                            Date thisUpdate, Date nextUpdate, byte[] nonce,
                                            ResponderMode mode) throws Exception {
        CertificateID certificateId = new JcaCertificateID(digestCalculator(), material.issuerCert(),
                serial);

        BasicOCSPRespBuilder builder;
        X509CertificateHolder[] chain;
        KeyPair signingKey;
        switch (mode) {
            case DELEGATED -> {
                builder = new BasicOCSPRespBuilder(
                        new JcaRespID(material.responderCert().getSubjectX500Principal()));
                chain = new X509CertificateHolder[]{new JcaX509CertificateHolder(material.responderCert())};
                signingKey = material.responderKeyPair();
            }
            case BAD_SIGNATURE -> {
                builder = new BasicOCSPRespBuilder(
                        new JcaRespID(material.issuerCert().getSubjectX500Principal()));
                chain = null;
                signingKey = material.leafKeyPair();
            }
            default -> {
                builder = new BasicOCSPRespBuilder(
                        new JcaRespID(material.issuerCert().getSubjectX500Principal()));
                chain = null;
                signingKey = material.issuerKeyPair();
            }
        }
        builder.addResponse(certificateId, status, thisUpdate, nextUpdate);
        if (nonce != null) {
            org.bouncycastle.asn1.x509.ExtensionsGenerator generator =
                    new org.bouncycastle.asn1.x509.ExtensionsGenerator();
            generator.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                    new DEROctetString(nonce));
            builder.setResponseExtensions(generator.generate());
        }
        BasicOCSPResp basic = builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(signingKey.getPrivate()),
                chain, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    public static byte[] revokedOcspResponse(Material material, Date thisUpdate, Date nextUpdate,
                                             byte[] nonce, ResponderMode mode) throws Exception {
        Date revocationDate = new Date(thisUpdate.getTime() - 1000);
        RevokedStatus revokedStatus = new RevokedStatus(revocationDate);
        return ocspResponse(material, revokedStatus, thisUpdate, nextUpdate, nonce, mode);
    }

    public static byte[] ocspResponseWithStatus(Material material, int ocspStatus) throws Exception {
        return new OCSPRespBuilder().build(ocspStatus, null).getEncoded();
    }

    public static byte[] crl(Material material, BigInteger revokedSerial,
                             Date thisUpdate, Date nextUpdate, boolean badSignature) throws Exception {
        return crlSignedBy(material,
                new JcaX509CertificateHolder(material.issuerCert()).getSubject(),
                badSignature ? material.leafKeyPair() : material.issuerKeyPair(),
                revokedSerial, thisUpdate, nextUpdate);
    }

    public static byte[] crlSignedBy(Material material, X500Name crlIssuer, KeyPair signingKey,
                                     BigInteger revokedSerial, Date thisUpdate, Date nextUpdate) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(crlIssuer, thisUpdate);
        if (revokedSerial != null) {
            builder.addCRLEntry(revokedSerial, new Date(thisUpdate.getTime() - 1000),
                    org.bouncycastle.asn1.x509.CRLReason.keyCompromise);
        }
        if (nextUpdate != null) {
            builder.setNextUpdate(nextUpdate);
        }
        X509CRLHolder holder = builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(signingKey.getPrivate()));
        return holder.getEncoded();
    }

    public static byte[] extractNonce(byte[] ocspRequestDer) throws Exception {
        org.bouncycastle.cert.ocsp.OCSPReq request =
                new org.bouncycastle.cert.ocsp.OCSPReq(ocspRequestDer);
        Extension extension = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (extension == null) {
            return null;
        }
        return DEROctetString.getInstance(extension.getExtnValue().getOctets()).getOctets();
    }

    private static org.bouncycastle.operator.DigestCalculator digestCalculator() throws Exception {
        return new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    public static X509Certificate issueSelfSignedRoot(KeyPair keyPair) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                ROOT_SUBJECT, BigInteger.valueOf(1), notBefore, notAfter, ROOT_SUBJECT, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")}));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }

    public static X509Certificate issueCa(X500Name issuer, KeyPair issuerKeyPair,
                                          X500Name subject, PublicKey publicKey, BigInteger serial) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate())));
    }

    public static X509Certificate issueLeaf(X500Name issuer, KeyPair issuerKeyPair, PublicKey publicKey,
                                            BigInteger serial, String ocspUrl, String crlUrl) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, LEAF_SUBJECT, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        if (ocspUrl != null) {
            builder.addExtension(Extension.authorityInfoAccess, false,
                    new AuthorityInformationAccess(AccessDescription.id_ad_ocsp,
                            new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
        }
        if (crlUrl != null) {
            builder.addExtension(Extension.cRLDistributionPoints, false,
                    new CRLDistPoint(new DistributionPoint[]{
                            new DistributionPoint(
                                    new DistributionPointName(new GeneralNames(
                                            new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl))),
                                    null, null)}));
        }
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate())));
    }

    public static X509Certificate issueResponder(X500Name issuer, KeyPair issuerKeyPair,
                                                 PublicKey publicKey) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(9), notBefore, notAfter, RESPONDER_SUBJECT, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate())));
    }

    /**
     * 自签名 TLS 服务端证书（用于本地 HttpsServer 测试；SAN 可指定）。
     */
    public static final X500Name TLS_CA_SUBJECT = new X500Name("CN=IOV Revocation Test TLS CA");

    /**
     * 自签名 TLS 服务端证书（用于本地 HttpsServer 测试；SAN 可指定）。
     */
    public static X509Certificate issueTlsServer(KeyPair keyPair, String dnsSan, String ipSan,
                                                 Date notBefore, Date notAfter) throws Exception {
        X500Name subject = new X500Name("CN=" + (dnsSan != null ? dnsSan : "localhost"));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(77), notBefore, notAfter, subject, keyPair.getPublic());
        addTlsServerExtensions(builder, dnsSan, ipSan);
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }

    /**
     * 自签名 TLS 信任锚 CA（无 SAN）。
     */
    public static X509Certificate issueTlsCa(KeyPair caKeyPair) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 3600_000);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                TLS_CA_SUBJECT, BigInteger.valueOf(5), notBefore, notAfter, TLS_CA_SUBJECT, caKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    /**
     * 由信任锚 CA 签发的 TLS 服务端叶子证书（serverAuth + SAN，强制校验其有效期）。
     */
    public static X509Certificate issueTlsLeaf(KeyPair caKeyPair, KeyPair serverKeyPair,
                                               String dnsSan, String ipSan,
                                               Date notBefore, Date notAfter) throws Exception {
        X500Name subject = new X500Name("CN=" + (dnsSan != null ? dnsSan : "localhost"));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                TLS_CA_SUBJECT, BigInteger.valueOf(78), notBefore, notAfter, subject, serverKeyPair.getPublic());
        addTlsServerExtensions(builder, dnsSan, ipSan);
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    private static void addTlsServerExtensions(JcaX509v3CertificateBuilder builder, String dnsSan, String ipSan)
            throws Exception {
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        java.util.List<GeneralName> names = new java.util.ArrayList<>();
        if (dnsSan != null) {
            names.add(new GeneralName(GeneralName.dNSName, dnsSan));
        }
        if (ipSan != null) {
            names.add(new GeneralName(GeneralName.iPAddress, ipSan));
        }
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(names.toArray(new GeneralName[0])));
    }

    private static X509Certificate toCertificate(X509CertificateHolder holder) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    public static String pem(String type, byte[] der) {
        String base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }
}
