package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusTrustValidationException;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 证书状态策略编排测试（FW-SEC-DSN-CR-010 §3.2/§6）：OCSP 优先、CRL 受控后备、
 * REVOKED 不被覆盖、总预算共享、默认关闭 fail-closed。
 */
class DefaultCertificateStatusCheckerTest {

    private static final String OCSP_URL = "https://ocsp.example.test/ocsp";
    private static final String CRL_URL = "https://crl.example.test/crl";

    private TestRevocationMaterial.Material material;
    private PkiRevocationProperties properties;
    private StubRevocationTransport transport;
    private DefaultCertificateStatusChecker checker;

    @BeforeEach
    void setUp() throws Exception {
        material = TestRevocationMaterial.generate(OCSP_URL, CRL_URL);
        properties = new PkiRevocationProperties();
        properties.setEnabled(true);
        properties.getRetry().setMaxAttempts(0);
        properties.setTotalTimeout(Duration.ofSeconds(2));
        properties.setIssuerCertPem(new String(material.issuerPem()));

        CryptoProperties cryptoProperties = new CryptoProperties();
        cryptoProperties.getPki().setProvider("step-ca");

        transport = new StubRevocationTransport();
        PkiRevocationMetrics metrics = new PkiRevocationMetrics(new SimpleMeterRegistry());
        CertificateDirectoryResolver resolver = new CertificateDirectoryResolver(
                new TestObjectProvider<>(null), properties, cryptoProperties);
        OcspCertificateStatusChecker ocspChecker = new OcspCertificateStatusChecker(
                transport, properties, metrics, Duration.ofMillis(500));
        CrlCertificateStatusChecker crlChecker = new CrlCertificateStatusChecker(
                transport, properties, metrics, Duration.ofMillis(500));
        checker = new DefaultCertificateStatusChecker(resolver, properties, ocspChecker, crlChecker, metrics);
    }

    private PkiClient.CertificateStatusQuery query() throws Exception {
        return new PkiClient.CertificateStatusQuery(
                material.leafDer(), material.leafCert().getSerialNumber().toString(16), null, Instant.now());
    }

    private void ocspResponds(org.bouncycastle.cert.ocsp.CertificateStatus status) {
        transport.onPost(body -> StubRevocationTransport.ok(compute(() ->
                TestRevocationMaterial.ocspResponse(material, status,
                        new Date(System.currentTimeMillis() - 60_000),
                        new Date(System.currentTimeMillis() + 3_600_000),
                        TestRevocationMaterial.extractNonce(body),
                        TestRevocationMaterial.ResponderMode.ISSUER))));
    }

    @Test
    void disabled_throwsConfiguration() throws Exception {
        properties.setEnabled(false);

        assertThatThrownBy(() -> checker.check(query()))
                .isInstanceOf(CertificateStatusConfigurationException.class);
    }

    @Test
    void modeOcsp_onlyQueriesOcsp() throws Exception {
        properties.setMode("ocsp");
        ocspResponds(CertificateStatus.GOOD);

        PkiClient.CertificateStatusResult result = checker.check(query());

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
        assertThat(result.subjectCommonName()).isEqualTo("revocation-leaf");
        assertThat(result.source()).isEqualTo(PkiClient.RevocationSource.OCSP);
        assertThat(transport.getCount).isZero();
    }

    @Test
    void modeCrl_onlyQueriesCrl() throws Exception {
        properties.setMode("crl");
        transport.onGet(uri -> StubRevocationTransport.ok(compute(() ->
                TestRevocationMaterial.crl(material, material.leafCert().getSerialNumber(),
                        new Date(System.currentTimeMillis() - 60_000),
                        new Date(System.currentTimeMillis() + 3_600_000), false))));

        PkiClient.CertificateStatusResult result = checker.check(query());

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.REVOKED);
        assertThat(result.source()).isEqualTo(PkiClient.RevocationSource.CRL);
        assertThat(transport.postCount).isZero();
    }

    @Test
    void ocspGood_doesNotQueryCrl() throws Exception {
        ocspResponds(CertificateStatus.GOOD);

        PkiClient.CertificateStatusResult result = checker.check(query());

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
        assertThat(transport.getCount).isZero();
    }

    @Test
    void ocspRevoked_isNotOverriddenByCrlGood() throws Exception {
        transport.onPost(body -> StubRevocationTransport.ok(compute(() ->
                TestRevocationMaterial.revokedOcspResponse(material,
                        new Date(System.currentTimeMillis() - 60_000),
                        new Date(System.currentTimeMillis() + 3_600_000),
                        TestRevocationMaterial.extractNonce(body),
                        TestRevocationMaterial.ResponderMode.ISSUER))));
        transport.onGet(uri -> StubRevocationTransport.ok(compute(() ->
                TestRevocationMaterial.crl(material, null,
                        new Date(System.currentTimeMillis() - 60_000),
                        new Date(System.currentTimeMillis() + 3_600_000), false))));

        PkiClient.CertificateStatusResult result = checker.check(query());

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.REVOKED);
        assertThat(result.source()).isEqualTo(PkiClient.RevocationSource.OCSP);
        assertThat(transport.getCount).isZero();
    }

    @Test
    void ocspUnknown_fallsBackToCrl() throws Exception {
        ocspResponds(new UnknownStatus());
        transport.onGet(uri -> StubRevocationTransport.ok(compute(() ->
                TestRevocationMaterial.crl(material, material.leafCert().getSerialNumber(),
                        new Date(System.currentTimeMillis() - 60_000),
                        new Date(System.currentTimeMillis() + 3_600_000), false))));

        PkiClient.CertificateStatusResult result = checker.check(query());

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.REVOKED);
        assertThat(result.source()).isEqualTo(PkiClient.RevocationSource.CRL);
        assertThat(transport.getCount).isEqualTo(1);
    }

    @Test
    void ocspDependencyFailure_fallsBackToCrl() throws Exception {
        transport.onPost(body -> {
            throw StubRevocationTransport.transportError(RevocationTransportException.Phase.CONNECT);
        });
        transport.onGet(uri -> StubRevocationTransport.ok(compute(() ->
                TestRevocationMaterial.crl(material, null,
                        new Date(System.currentTimeMillis() - 60_000),
                        new Date(System.currentTimeMillis() + 3_600_000), false))));

        PkiClient.CertificateStatusResult result = checker.check(query());

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
        assertThat(result.source()).isEqualTo(PkiClient.RevocationSource.CRL);
    }

    @Test
    void ocspTrustFailure_failsClosedWithoutCrlFallback() throws Exception {
        transport.onPost(body -> {
            throw StubRevocationTransport.transportError(RevocationTransportException.Phase.TLS);
        });

        assertThatThrownBy(() -> checker.check(query()))
                .isInstanceOf(CertificateStatusTrustValidationException.class);
        assertThat(transport.getCount).isZero();
    }

    @Test
    void invalidMode_throwsConfiguration() throws Exception {
        properties.setMode("bogus");

        assertThatThrownBy(() -> checker.check(query()))
                .isInstanceOf(CertificateStatusConfigurationException.class);
    }

    @Test
    void noEndpointsAtAll_throwsConfigurationNotReady() throws Exception {
        TestRevocationMaterial.Material noEndpoints = TestRevocationMaterial.generate(null, null);
        properties.setIssuerCertPem(new String(noEndpoints.issuerPem()));
        PkiClient.CertificateStatusQuery query = new PkiClient.CertificateStatusQuery(
                noEndpoints.leafDer(), noEndpoints.leafCert().getSerialNumber().toString(16), null, Instant.now());

        assertThatThrownBy(() -> checker.check(query))
                .isInstanceOf(CertificateStatusConfigurationException.class)
                .hasMessageContaining("NOT_READY");
    }

    @Test
    void ocspEndpointMissing_fallsBackToCrl() throws Exception {
        TestRevocationMaterial.Material noAia = TestRevocationMaterial.generate(null, CRL_URL);
        properties.setIssuerCertPem(new String(noAia.issuerPem()));
        PkiClient.CertificateStatusQuery query = new PkiClient.CertificateStatusQuery(
                noAia.leafDer(), noAia.leafCert().getSerialNumber().toString(16), null, Instant.now());
        transport.onGet(uri -> StubRevocationTransport.ok(compute(() ->
                TestRevocationMaterial.crl(noAia, noAia.leafCert().getSerialNumber(),
                        new Date(System.currentTimeMillis() - 60_000),
                        new Date(System.currentTimeMillis() + 3_600_000), false))));

        PkiClient.CertificateStatusResult result = checker.check(query);

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.REVOKED);
        assertThat(transport.postCount).isZero();
    }

    @Test
    void dependencyFailureWithoutCrl_throwsDependencyUnavailable() throws Exception {
        TestRevocationMaterial.Material noCdp = TestRevocationMaterial.generate(OCSP_URL, null);
        properties.setIssuerCertPem(new String(noCdp.issuerPem()));
        PkiClient.CertificateStatusQuery query = new PkiClient.CertificateStatusQuery(
                noCdp.leafDer(), noCdp.leafCert().getSerialNumber().toString(16), null, Instant.now());
        transport.onPost(body -> {
            throw StubRevocationTransport.transportError(RevocationTransportException.Phase.CONNECT);
        });

        assertThatThrownBy(() -> checker.check(query))
                .isInstanceOf(CertificateStatusDependencyUnavailableException.class);
    }

    private interface ThrowingSupplier {
        byte[] get() throws Exception;
    }

    private static byte[] compute(ThrowingSupplier supplier) {
        try {
            return supplier.get();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
