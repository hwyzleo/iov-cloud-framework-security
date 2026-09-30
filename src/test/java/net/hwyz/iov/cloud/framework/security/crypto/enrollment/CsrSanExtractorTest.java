package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CsrSanExtractor} 单元测试：验证从 CSR 提取各类 SAN（尤其 URI）。
 */
class CsrSanExtractorTest {

    private byte[] csrWithSans(GeneralName... names) throws Exception {
        KeyPair keyPair = TestPkiMaterial.generateKeyPair();
        X500Name subject = new X500Name("CN=00000000000000000000000000000001");
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        if (names.length > 0) {
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        }
        PKCS10CertificationRequest csr = builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate()));
        return csr.getEncoded();
    }

    @Test
    void extractSans_shouldReturnUriSan() throws Exception {
        byte[] csr = csrWithSans(
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "urn:ecu-uid:00000000000000000000000000000001"));

        List<String> sans = CsrSanExtractor.extractSans(csr);

        assertEquals(List.of("urn:ecu-uid:00000000000000000000000000000001"), sans);
    }

    @Test
    void extractSans_shouldReturnMixedSansInOrder() throws Exception {
        byte[] csr = csrWithSans(
                new GeneralName(GeneralName.dNSName, "tbox.example.com"),
                new GeneralName(GeneralName.uniformResourceIdentifier, "urn:ecu-uid:abc"),
                new GeneralName(GeneralName.rfc822Name, "dev@example.com"));

        List<String> sans = CsrSanExtractor.extractSans(csr);

        assertEquals(3, sans.size());
        assertTrue(sans.contains("tbox.example.com"));
        assertTrue(sans.contains("urn:ecu-uid:abc"));
        assertTrue(sans.contains("dev@example.com"));
    }

    @Test
    void extractSans_shouldReturnIpSan() throws Exception {
        byte[] csr = csrWithSans(
                new GeneralName(GeneralName.iPAddress, "192.168.1.10"));

        List<String> sans = CsrSanExtractor.extractSans(csr);

        assertEquals(List.of("192.168.1.10"), sans);
    }

    @Test
    void extractSans_shouldReturnEmpty_whenNoSanExtension() throws Exception {
        byte[] csr = csrWithSans();

        List<String> sans = CsrSanExtractor.extractSans(csr);

        assertTrue(sans.isEmpty());
    }

    @Test
    void extractSans_shouldAcceptPemCsr() throws Exception {
        byte[] der = csrWithSans(
                new GeneralName(GeneralName.uniformResourceIdentifier, "urn:ecu-uid:xyz"));
        String pem = TestPkiMaterial.pem("CERTIFICATE REQUEST", der);

        List<String> sans = CsrSanExtractor.extractSans(pem.getBytes());

        assertEquals(List.of("urn:ecu-uid:xyz"), sans);
    }

    @Test
    void extractSans_shouldFail_whenCsrEmpty() {
        assertThrows(InvalidCertificateRequestException.class,
                () -> CsrSanExtractor.extractSans(new byte[0]));
    }

    @Test
    void extractSans_shouldFail_whenNotACsr() {
        assertThrows(InvalidCertificateRequestException.class,
                () -> CsrSanExtractor.extractSans("not-a-csr".getBytes()));
    }
}
