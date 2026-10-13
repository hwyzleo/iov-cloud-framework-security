package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusProtocolException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusTrustValidationException;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.UnknownStatus;
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
 * 标准 OCSP 检查器协议与故障分类测试（FW-SEC-DSN-CR-010 §3.1/§10）。
 */
class OcspCertificateStatusCheckerTest {

    private static final URI OCSP_URI = URI.create("https://ocsp.example.test/ocsp");

    private TestRevocationMaterial.Material material;
    private PkiRevocationProperties properties;
    private StubRevocationTransport transport;
    private OcspCertificateStatusChecker checker;
    private Instant decisionAt;

    @BeforeEach
    void setUp() throws Exception {
        material = TestRevocationMaterial.generate(OCSP_URI.toString(), "https://crl.example.test/crl");
        properties = new PkiRevocationProperties();
        properties.setEnabled(true);
        properties.getRetry().setMaxAttempts(0);
        transport = new StubRevocationTransport();
        checker = new OcspCertificateStatusChecker(transport, properties,
                new PkiRevocationMetrics(new SimpleMeterRegistry()), Duration.ofMillis(500));
        decisionAt = Instant.now();
    }

    private CertificateStatusContext context() {
        return new CertificateStatusContext(material.leafCert(), material.issuerCert(), "revocation-leaf",
                OCSP_URI, null, "legacy-rest");
    }

    private Date in(long seconds) {
        return new Date(System.currentTimeMillis() + seconds * 1000);
    }

    @Test
    void good_returnsGoodWithValidityFromLeaf() throws Exception {
        transport.onPost(body -> StubRevocationTransport.ok(TestRevocationMaterial.ocspResponse(
                material, CertificateStatus.GOOD, in(-60), in(3600),
                TestRevocationMaterial.extractNonce(body), TestRevocationMaterial.ResponderMode.ISSUER)));

        PkiClient.CertificateStatusResult result = checker.check(context(), decisionAt, decisionAt.plusSeconds(1));

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
        assertThat(result.source()).isEqualTo(PkiClient.RevocationSource.OCSP);
        assertThat(result.notBefore()).isEqualTo(material.leafCert().getNotBefore().toInstant());
        assertThat(result.notAfter()).isEqualTo(material.leafCert().getNotAfter().toInstant());
        assertThat(result.nextUpdate()).isNotNull();
    }

    @Test
    void revoked_returnsRevoked() throws Exception {
        transport.onPost(body -> StubRevocationTransport.ok(TestRevocationMaterial.revokedOcspResponse(
                material, in(-60), in(3600),
                TestRevocationMaterial.extractNonce(body), TestRevocationMaterial.ResponderMode.ISSUER)));

        PkiClient.CertificateStatusResult result = checker.check(context(), decisionAt, decisionAt.plusSeconds(1));

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.REVOKED);
    }

    @Test
    void unknown_returnsUnknown_notGood() throws Exception {
        transport.onPost(body -> StubRevocationTransport.ok(TestRevocationMaterial.ocspResponse(
                material, new UnknownStatus(), in(-60), in(3600),
                TestRevocationMaterial.extractNonce(body), TestRevocationMaterial.ResponderMode.ISSUER)));

        PkiClient.CertificateStatusResult result = checker.check(context(), decisionAt, decisionAt.plusSeconds(1));

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.UNKNOWN);
    }

    @Test
    void delegatedResponder_isAccepted() throws Exception {
        transport.onPost(body -> StubRevocationTransport.ok(TestRevocationMaterial.ocspResponse(
                material, CertificateStatus.GOOD, in(-60), in(3600),
                TestRevocationMaterial.extractNonce(body), TestRevocationMaterial.ResponderMode.DELEGATED)));

        PkiClient.CertificateStatusResult result = checker.check(context(), decisionAt, decisionAt.plusSeconds(1));

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
    }

    @Test
    void badSignature_throwsTrustValidation() {
        transport.onPost(body -> StubRevocationTransport.ok(assertThrowsOccurs(() ->
                TestRevocationMaterial.ocspResponse(material, CertificateStatus.GOOD, in(-60), in(3600),
                        TestRevocationMaterial.extractNonce(body), TestRevocationMaterial.ResponderMode.BAD_SIGNATURE))));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusTrustValidationException.class);
    }

    @Test
    void nonceRequiredButMissing_throwsProtocol() {
        transport.onPost(body -> StubRevocationTransport.ok(assertThrowsOccurs(() ->
                TestRevocationMaterial.ocspResponse(material, CertificateStatus.GOOD, in(-60), in(3600),
                        null, TestRevocationMaterial.ResponderMode.ISSUER))));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusProtocolException.class)
                .hasMessageContaining("nonce");
    }

    @Test
    void nonceMismatch_throwsProtocol() {
        transport.onPost(body -> StubRevocationTransport.ok(assertThrowsOccurs(() ->
                TestRevocationMaterial.ocspResponse(material, CertificateStatus.GOOD, in(-60), in(3600),
                        new byte[16], TestRevocationMaterial.ResponderMode.ISSUER))));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusProtocolException.class);
    }

    @Test
    void nonceDisabled_passesWithoutNonce() throws Exception {
        properties.getOcsp().setNoncePolicy("disabled");
        transport.onPost(body -> {
            assertThat(TestRevocationMaterial.extractNonce(body)).isNull();
            return StubRevocationTransport.ok(assertThrowsOccurs(() ->
                    TestRevocationMaterial.ocspResponse(material, CertificateStatus.GOOD, in(-60), in(3600),
                            null, TestRevocationMaterial.ResponderMode.ISSUER)));
        });

        PkiClient.CertificateStatusResult result = checker.check(context(), decisionAt, decisionAt.plusSeconds(1));
        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
    }

    @Test
    void staleResponse_throwsProtocol() {
        transport.onPost(body -> StubRevocationTransport.ok(assertThrowsOccurs(() ->
                TestRevocationMaterial.ocspResponse(material, CertificateStatus.GOOD,
                        in(-7200), in(-3600),
                        TestRevocationMaterial.extractNonce(body), TestRevocationMaterial.ResponderMode.ISSUER))));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusProtocolException.class)
                .hasMessageContaining("stale");
    }

    @Test
    void wrongSerialInResponse_throwsProtocol() {
        transport.onPost(body -> StubRevocationTransport.ok(assertThrowsOccurs(() ->
                TestRevocationMaterial.ocspResponseForSerial(material,
                        material.leafCert().getSerialNumber().add(BigInteger.ONE), CertificateStatus.GOOD,
                        in(-60), in(3600),
                        TestRevocationMaterial.extractNonce(body), TestRevocationMaterial.ResponderMode.ISSUER))));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusProtocolException.class);
    }

    @Test
    void malformedBody_throwsProtocol() {
        transport.onPost(body -> StubRevocationTransport.ok(new byte[]{1, 2, 3}));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusProtocolException.class);
    }

    @Test
    void tryLaterStatus_throwsDependencyUnavailable() throws Exception {
        byte[] response = TestRevocationMaterial.ocspResponseWithStatus(material, OCSPRespBuilder.TRY_LATER);
        transport.onPost(body -> StubRevocationTransport.ok(response));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusDependencyUnavailableException.class);
    }

    @Test
    void unauthorizedStatus_throwsConfiguration() throws Exception {
        byte[] response = TestRevocationMaterial.ocspResponseWithStatus(material, OCSPRespBuilder.UNAUTHORIZED);
        transport.onPost(body -> StubRevocationTransport.ok(response));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusConfigurationException.class);
    }

    @Test
    void http500_throwsDependencyUnavailable_withoutRetry() {
        transport.onPost(body -> StubRevocationTransport.status(500));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusDependencyUnavailableException.class);
        assertThat(transport.postCount).isEqualTo(1);
    }

    @Test
    void http503_retriesOnceWithinBudget_thenDependencyUnavailable() {
        properties.getRetry().setMaxAttempts(2);
        transport.onPost(body -> StubRevocationTransport.status(503));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(2)))
                .isInstanceOf(CertificateStatusDependencyUnavailableException.class);
        assertThat(transport.postCount).isEqualTo(2);
    }

    @Test
    void http429_throwsDependencyUnavailable_withoutRetry() {
        properties.getRetry().setMaxAttempts(1);
        transport.onPost(body -> StubRevocationTransport.status(429));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(2)))
                .isInstanceOf(CertificateStatusDependencyUnavailableException.class);
        assertThat(transport.postCount).isEqualTo(1);
    }

    @Test
    void http400_throwsProtocol() {
        transport.onPost(body -> StubRevocationTransport.status(400));

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusProtocolException.class);
    }

    @Test
    void tlsFailure_throwsTrustValidation_withoutRetry() {
        properties.getRetry().setMaxAttempts(1);
        transport.onPost(body -> {
            throw StubRevocationTransport.transportError(RevocationTransportException.Phase.TLS);
        });

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(2)))
                .isInstanceOf(CertificateStatusTrustValidationException.class);
        assertThat(transport.postCount).isEqualTo(1);
    }

    @Test
    void dnsFailure_throwsDependencyUnavailable_withoutRetry() {
        properties.getRetry().setMaxAttempts(1);
        transport.onPost(body -> {
            throw StubRevocationTransport.transportError(RevocationTransportException.Phase.DNS);
        });

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(2)))
                .isInstanceOf(CertificateStatusDependencyUnavailableException.class);
        assertThat(transport.postCount).isEqualTo(1);
    }

    @Test
    void connectFailure_retriesOnceWithinBudget() {
        properties.getRetry().setMaxAttempts(2);
        transport.onPost(body -> {
            throw StubRevocationTransport.transportError(RevocationTransportException.Phase.CONNECT);
        });

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(2)))
                .isInstanceOf(CertificateStatusDependencyUnavailableException.class);
        assertThat(transport.postCount).isEqualTo(2);
    }

    @Test
    void readTimeout_throwsOutcomeUnknown_withoutRetry() {
        properties.getRetry().setMaxAttempts(1);
        transport.onPost(body -> {
            throw StubRevocationTransport.transportError(RevocationTransportException.Phase.READ_TIMEOUT);
        });

        assertThatThrownBy(() -> checker.check(context(), decisionAt, decisionAt.plusSeconds(2)))
                .isInstanceOf(net.hwyz.iov.cloud.framework.security.crypto.exception
                        .CertificateStatusOutcomeUnknownException.class);
        assertThat(transport.postCount).isEqualTo(1);
    }

    @Test
    void noOcspEndpoint_throwsConfiguration() {
        CertificateStatusContext noOcsp = new CertificateStatusContext(
                material.leafCert(), material.issuerCert(), "revocation-leaf", null, null, "legacy-rest");

        assertThatThrownBy(() -> checker.check(noOcsp, decisionAt, decisionAt.plusSeconds(1)))
                .isInstanceOf(CertificateStatusConfigurationException.class);
    }

    private interface ThrowingSupplier {
        byte[] get() throws Exception;
    }

    private static byte[] assertThrowsOccurs(ThrowingSupplier supplier) {
        try {
            return supplier.get();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
