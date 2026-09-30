package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * 测试用 PKI 材料生成工具（Root CA → Intermediate CA → Leaf / CSR）。
 */
public final class TestPkiMaterial {

    public static final X500Name ROOT_SUBJECT = new X500Name("CN=IOV Test Root CA");
    public static final X500Name INTERMEDIATE_SUBJECT = new X500Name("CN=IOV Test Intermediate CA");
    public static final X500Name LEAF_SUBJECT = new X500Name("CN=TBOX-00000000000000000000000000000001");

    private TestPkiMaterial() {
    }

    public record Pki(
            KeyPair rootKeyPair,
            X509Certificate rootCert,
            KeyPair intermediateKeyPair,
            X509Certificate intermediateCert,
            KeyPair leafKeyPair,
            X509Certificate leafCert,
            byte[] csrPem,
            byte[] chainPem
    ) {}

    /**
     * 生成含 clientAuth EKU 与 SAN 的叶子证书，CSR 与叶子公钥一致。
     *
     * @param withClientAuthEku 叶子是否带 CLIENT_AUTH EKU
     * @param san               叶子 SAN（可为 null）
     */
    public static Pki generate(boolean withClientAuthEku, String san) throws Exception {
        KeyPair rootKeyPair = generateKeyPair();
        X509Certificate rootCert = issueSelfSigned(ROOT_SUBJECT, rootKeyPair, BigInteger.valueOf(1));

        KeyPair intermediateKeyPair = generateKeyPair();
        X509Certificate intermediateCert = issueCa(ROOT_SUBJECT, rootKeyPair,
                INTERMEDIATE_SUBJECT, intermediateKeyPair.getPublic(), BigInteger.valueOf(2));

        KeyPair leafKeyPair = generateKeyPair();
        X509Certificate leafCert = issueLeaf(INTERMEDIATE_SUBJECT, intermediateKeyPair,
                LEAF_SUBJECT, leafKeyPair.getPublic(), BigInteger.valueOf(3),
                withClientAuthEku, san);

        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(LEAF_SUBJECT, leafKeyPair.getPublic());
        PKCS10CertificationRequest csr = csrBuilder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(leafKeyPair.getPrivate()));
        byte[] csrPem = pem("CERTIFICATE REQUEST", csr.getEncoded()).getBytes();

        byte[] chainPem = (pem("CERTIFICATE", intermediateCert.getEncoded())
                + pem("CERTIFICATE", rootCert.getEncoded())).getBytes();

        return new Pki(rootKeyPair, rootCert, intermediateKeyPair, intermediateCert,
                leafKeyPair, leafCert, csrPem, chainPem);
    }

    public static Pki generate() throws Exception {
        return generate(true, "TBOX-00000000000000000000000000000001");
    }

    /**
     * 生成叶子证书携带 URI 类型 SAN（如 {@code urn:ecu-uid:<uid>}）的完整材料，
     * 用于 subject-rule 前缀校验测试。
     */
    public static Pki generateWithUriSan(String uriSan) throws Exception {
        KeyPair rootKeyPair = generateKeyPair();
        X509Certificate rootCert = issueSelfSigned(ROOT_SUBJECT, rootKeyPair, BigInteger.valueOf(1));

        KeyPair intermediateKeyPair = generateKeyPair();
        X509Certificate intermediateCert = issueCa(ROOT_SUBJECT, rootKeyPair,
                INTERMEDIATE_SUBJECT, intermediateKeyPair.getPublic(), BigInteger.valueOf(2));

        KeyPair leafKeyPair = generateKeyPair();
        X509Certificate leafCert = issueLeafWithUriSan(INTERMEDIATE_SUBJECT, intermediateKeyPair,
                LEAF_SUBJECT, leafKeyPair.getPublic(), BigInteger.valueOf(3), uriSan);

        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(LEAF_SUBJECT, leafKeyPair.getPublic());
        PKCS10CertificationRequest csr = csrBuilder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(leafKeyPair.getPrivate()));
        byte[] csrPem = pem("CERTIFICATE REQUEST", csr.getEncoded()).getBytes();

        byte[] chainPem = (pem("CERTIFICATE", intermediateCert.getEncoded())
                + pem("CERTIFICATE", rootCert.getEncoded())).getBytes();

        return new Pki(rootKeyPair, rootCert, intermediateKeyPair, intermediateCert,
                leafKeyPair, leafCert, csrPem, chainPem);
    }

    public static X509Certificate issueLeafWithUriSan(X500Name issuer, KeyPair issuerKeyPair,
                                                      X500Name subject, PublicKey publicKey, BigInteger serial,
                                                      String uriSan) throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, uriSan)));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate())));
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    public static X509Certificate issueSelfSigned(X500Name subject, KeyPair keyPair, BigInteger serial) throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        // 作为 HTTPS 服务端证书时需覆盖连接主机名（JDK HttpClient 强制主机名校验）
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, "localhost"),
                        new GeneralName(GeneralName.iPAddress, "127.0.0.1")}));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }

    public static X509Certificate issueCa(X500Name issuer, KeyPair issuerKeyPair,
                                          X500Name subject, PublicKey publicKey, BigInteger serial) throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate())));
    }

    public static X509Certificate issueLeaf(X500Name issuer, KeyPair issuerKeyPair,
                                            X500Name subject, PublicKey publicKey, BigInteger serial,
                                            boolean withClientAuthEku, String san) throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        if (withClientAuthEku) {
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        }
        if (san != null) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, san)));
        }
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate())));
    }

    private static X509Certificate toCertificate(X509CertificateHolder holder) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    public static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    public static List<byte[]> derList(byte[]... ders) {
        return java.util.Arrays.asList(ders);
    }
}
