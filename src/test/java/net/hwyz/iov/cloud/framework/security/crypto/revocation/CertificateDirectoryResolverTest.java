package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusProtocolException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiDependencyUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 证书目录解析器测试（FW-SEC-DSN-CR-010 §3/§8，决策 RD-010-7：调用方携带叶子证书优先）。
 */
class CertificateDirectoryResolverTest {

    private static final String OCSP_URL = "https://ocsp.example.test/ocsp";
    private static final String CRL_URL = "https://crl.example.test/crl";

    private TestRevocationMaterial.Material material;
    private PkiRevocationProperties properties;
    private CryptoProperties cryptoProperties;

    @BeforeEach
    void setUp() throws Exception {
        material = TestRevocationMaterial.generate(OCSP_URL, CRL_URL);
        properties = new PkiRevocationProperties();
        properties.setEnabled(true);
        cryptoProperties = new CryptoProperties();
        cryptoProperties.getPki().setProvider("legacy-rest");
    }

    private CertificateDirectoryResolver resolver(PkiClient client) {
        return new CertificateDirectoryResolver(new TestObjectProvider<>(client), properties, cryptoProperties);
    }

    private PkiClient.CertificateStatusQuery query(byte[] leaf, String fingerprint) {
        return new PkiClient.CertificateStatusQuery(
                material.leafCert().getSerialNumber().toString(16), fingerprint, leaf,
                Instant.parse("2026-10-12T00:00:00Z"));
    }

    @Test
    void callerProvidedLeaf_resolvesIssuerFromConfigAndEndpointsFromExtensions() throws Exception {
        properties.setIssuerCertPem(new String(material.issuerPem()));

        CertificateStatusContext context = resolver(null).resolve(query(material.leafDer(), null));

        assertThat(context.leafCertificate()).isEqualTo(material.leafCert());
        assertThat(context.issuerCertificate()).isEqualTo(material.issuerCert());
        assertThat(context.ocspUri()).hasToString(OCSP_URL);
        assertThat(context.crlUri()).hasToString(CRL_URL);
        assertThat(context.provider()).isEqualTo("legacy-rest");
    }

    @Test
    void explicitOverrides_takePrecedenceOverAiaAndCdp() throws Exception {
        properties.setIssuerCertPem(new String(material.issuerPem()));
        properties.getOcsp().setUrl("https://override.example/ocsp");
        properties.getCrl().setUrl("https://override.example/crl");

        CertificateStatusContext context = resolver(null).resolve(query(material.leafDer(), null));

        assertThat(context.ocspUri()).hasToString("https://override.example/ocsp");
        assertThat(context.crlUri()).hasToString("https://override.example/crl");
    }

    @Test
    void fingerprintMismatch_throwsProtocol() throws Exception {
        properties.setIssuerCertPem(new String(material.issuerPem()));

        assertThatThrownBy(() -> resolver(null).resolve(query(material.leafDer(), "deadbeef")))
                .isInstanceOf(CertificateStatusProtocolException.class)
                .hasMessageContaining("fingerprint");
    }

    @Test
    void fingerprintMatch_passes() throws Exception {
        properties.setIssuerCertPem(new String(material.issuerPem()));
        String fingerprint = net.hwyz.iov.cloud.framework.security.crypto.enrollment.EnrollmentRecord
                .fingerprintHex(material.leafDer());

        CertificateStatusContext context = resolver(null).resolve(query(material.leafDer(), fingerprint));

        assertThat(context.leafCertificate()).isEqualTo(material.leafCert());
    }

    @Test
    void serialMismatch_throwsProtocol() throws Exception {
        properties.setIssuerCertPem(new String(material.issuerPem()));
        PkiClient.CertificateStatusQuery wrong = new PkiClient.CertificateStatusQuery(
                "ff", null, material.leafDer(), Instant.now());

        assertThatThrownBy(() -> resolver(null).resolve(wrong))
                .isInstanceOf(CertificateStatusProtocolException.class)
                .hasMessageContaining("serial");
    }

    @Test
    void unparseableLeaf_throwsProtocol() {
        assertThatThrownBy(() -> resolver(null).resolve(query(new byte[]{1, 2, 3}, null)))
                .isInstanceOf(CertificateStatusProtocolException.class);
    }

    @Test
    void missingIssuerConfiguration_throwsConfiguration() throws Exception {
        assertThatThrownBy(() -> resolver(null).resolve(query(material.leafDer(), null)))
                .isInstanceOf(CertificateStatusConfigurationException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void configuredIssuerDoesNotMatch_throwsProtocol() throws Exception {
        properties.setIssuerCertPem(new String(material.rootPem()));

        assertThatThrownBy(() -> resolver(null).resolve(query(material.leafDer(), null)))
                .isInstanceOf(CertificateStatusProtocolException.class);
    }

    @Test
    void withoutLeaf_fallsBackToProviderDirectory() throws Exception {
        PkiClient directory = new FakeDirectoryPkiClient(material);
        properties.setIssuerCertPem(new String(material.issuerPem()));

        CertificateStatusContext context = resolver(directory).resolve(new PkiClient.CertificateStatusQuery(
                material.leafCert().getSerialNumber().toString(16), null, null, Instant.now()));

        assertThat(context.leafCertificate()).isEqualTo(material.leafCert());
        assertThat(context.ocspUri()).hasToString(OCSP_URL);
    }

    @Test
    void withoutLeafAndProviderWithoutDirectory_throwsConfiguration() {
        PkiClient noDirectory = new PkiClient() {
            @Override
            public ApplyResponse submit(ApplyCommand command) {
                throw new UnsupportedOperationException();
            }

            @Override
            public StatusResponse getStatus(String requestId) {
                throw new UnsupportedOperationException();
            }

            @Override
            public CertificateResponse getCertificate(String requestId) {
                throw new UnsupportedOperationException();
            }

            @Override
            public CertificateResponse queryCertificate(String serialNumber) {
                throw new PkiDependencyUnavailableException("step-ca does not provide a serial directory");
            }
        };

        assertThatThrownBy(() -> resolver(noDirectory).resolve(new PkiClient.CertificateStatusQuery(
                "1234567890abcdef", null, null, Instant.now())))
                .isInstanceOf(CertificateStatusConfigurationException.class)
                .hasMessageContaining("leafCertificateDer");
    }

    private static final class FakeDirectoryPkiClient implements PkiClient {
        private final TestRevocationMaterial.Material material;

        FakeDirectoryPkiClient(TestRevocationMaterial.Material material) {
            this.material = material;
        }

        @Override
        public ApplyResponse submit(ApplyCommand command) {
            throw new UnsupportedOperationException();
        }

        @Override
        public StatusResponse getStatus(String requestId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CertificateResponse getCertificate(String requestId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CertificateResponse queryCertificate(String serialNumber) {
            try {
                return new CertificateResponse("req", material.leafDer(), material.issuerPem(),
                        material.leafCert().getSerialNumber().toString(16), null, null);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
