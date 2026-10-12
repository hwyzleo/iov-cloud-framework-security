package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusProtocolException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusTrustValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 标准 CRL 检查器协议与故障分类测试（FW-SEC-DSN-CR-010 §3.2/§10）。
 */
class CrlCertificateStatusCheckerTest {

    private static final URI CRL_URI = URI.create("https://crl.example.test/crl");

    private TestRevocationMaterial.Material material;
    private PkiRevocationProperties properties;
    private StubRevocationTransport transport;
    private CrlCertificateStatusChecker checker;
    private Instant decisionAt;

    @BeforeEach
    void setUp() throws Exception {
        material = TestRevocationMaterial.generate("https://ocsp.example.test/ocsp", CRL_URI.toString());
        properties = new PkiRevocationProperties();
        properties.setEnabled(true);
        properties.getRetry().setMaxAttempts(0);
        transport = new StubRevocationTransport();
        checker = new CrlCertificateStatusChecker(transport, properties,
                new PkiRevocationMetrics(new SimpleMeterRegistry()), Duration.ofMillis(500));
        decisionAt = Instant.now();
    }

    private CertificateStatusContext context() {
        return new CertificateStatusContext(material.leafCert(), material.issuerCert(), null, CRL_URI, "legacy-rest");
    }

    private Date in(long seconds) {
        return new Date(System.currentTimeMillis() + seconds * 1000);
    }

    @Test
    void notRevoked_returnsGood() throws Exception {
        byte[] crl = TestRevocationMaterial.crl(material, null, in(-60), in(3600), false);
        transport.onGet(uri -> StubRevocationTransport.ok(crl));

        PkiClient.CertificateStatusResult result = checker.check(context(), decisionAt, decisionAt.plusSeconds(1));

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
        assertThat(result.source()).isEqualTo(PkiClient.RevocationSource.CRL);
    }

    @Test
    void revokedSerial_returnsRevoked() throws Exception {
        byte[] crl = TestRevocationMaterial.crl(material, material.leafCert().getSerialNumber(),
                in(-60), in(3600), false);
        transport.onGet(uri -> StubRevocationTransport.ok(crl));

        PkiClient.CertificateStatusResult result = checker.check(context(), decisionAt, decisionAt.plusSeconds(1));

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.REVOKED);
    }

    @Test
    void badSignature_throwsTrustValidation() throws Exception {
        byte[] crl = TestRevocationMaterial.crl(material, null, in(-60), in(3600), true);
        transport.onGet(uri -> StubRevocationTransport.ok(crl));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusTrustValidationException.class);
    }

    @Test
    void wrongIssuer_throwsTrustValidation() throws Exception {
        byte[] crl = TestRevocationMaterial.crlSignedBy(material,
                TestRevocationMaterial.ROOT_SUBJECT, material.rootKeyPair(),
                null, in(-60), in(3600));
        transport.onGet(uri -> StubRevocationTransport.ok(crl));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusTrustValidationException.class);
    }

    @Test
    void expiredCrl_returnsUnknown_notGood() throws Exception {
        byte[] crl = TestRevocationMaterial.crl(material, null, in(-7200), in(-3600), false);
        transport.onGet(uri -> StubRevocationTransport.ok(crl));

        PkiClient.CertificateStatusResult result = checker.check(context(), decisionAt, decisionAt.plusSeconds(1));

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.UNKNOWN);
    }

    @Test
    void emptyBody_throwsProtocol() {
        transport.onGet(uri -> StubRevocationTransport.ok(new byte[0]));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusProtocolException.class);
    }

    @Test
    void http404_throwsProtocol() {
        transport.onGet(uri -> StubRevocationTransport.status(404));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusProtocolException.class);
    }

    @Test
    void http503_retriesOnceWithinBudget_thenDependencyUnavailable() {
        properties.getRetry().setMaxAttempts(1);
        transport.onGet(uri -> StubRevocationTransport.status(503));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(2)))
                .isInstanceOf(CertificateStatusDependencyUnavailableException.class);
        assertThat(transport.getCount).isEqualTo(2);
    }

    @Test
    void noCrlEndpoint_throwsConfiguration() {
        CertificateStatusContext noCrl = new CertificateStatusContext(
                material.leafCert(), material.issuerCert(), null, null, "legacy-rest");

        assertThatThrownBy(() -> checker.check(noCrl, decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusConfigurationException.class);
    }

    @Test
    void revokedOtherSerial_returnsGood() throws Exception {
        byte[] crl = TestRevocationMaterial.crl(material, BigInteger.valueOf(999), in(-60), in(3600), false);
        transport.onGet(uri -> StubRevocationTransport.ok(crl));

        PkiClient.CertificateStatusResult result = checker.check(context(), decisionAt, decisionAt.plusSeconds(1));

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
    }
}
