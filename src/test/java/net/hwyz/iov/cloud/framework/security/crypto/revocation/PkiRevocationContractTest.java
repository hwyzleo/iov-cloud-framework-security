package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 平台签发测试证书 + 真实测试 OCSP responder / CRL CDP 的黑盒契约测试（FW-SEC-DSN-CR-010 §10）。
 * <p>
 * 覆盖 GOOD→REVOKED 转换、OCSP 不可用时 CRL 后备，以及真实 TLS 私有根信任。
 */
class PkiRevocationContractTest {

    private HttpsServer server;
    private HttpRevocationTransport transport;
    private DefaultCertificateStatusChecker checker;
    private CertificateStatusTemplate template;
    private TestRevocationMaterial.Material material;

    private final AtomicReference<CertificateStatus> ocspStatus = new AtomicReference<>(CertificateStatus.GOOD);
    private final AtomicBoolean ocspFails = new AtomicBoolean(false);
    private final AtomicBoolean crlRevoked = new AtomicBoolean(false);
    private final AtomicReference<TestRevocationMaterial.Material> materialRef = new AtomicReference<>();

    @BeforeEach
    void setUp() throws Exception {
        KeyPair serverKeyPair = TestRevocationMaterial.generateKeyPair();
        X509Certificate serverCert = TestRevocationMaterial.issueTlsServer(serverKeyPair, "localhost", "127.0.0.1",
                new Date(System.currentTimeMillis() - 3600_000),
                new Date(System.currentTimeMillis() + 3600_000));

        server = startServer(serverKeyPair, serverCert);
        int port = server.getAddress().getPort();

        material = TestRevocationMaterial.generate(
                "https://127.0.0.1:" + port + "/ocsp", "https://127.0.0.1:" + port + "/crl");
        materialRef.set(material);

        CryptoProperties cryptoProperties = new CryptoProperties();
        cryptoProperties.getPki().setProvider("step-ca");
        cryptoProperties.getPki().getTls().setTrustedCertsPem(
                TestRevocationMaterial.pem("CERTIFICATE", serverCert.getEncoded()));

        PkiRevocationProperties properties = new PkiRevocationProperties();
        properties.setEnabled(true);
        properties.setMode("ocsp-then-crl");
        properties.setTotalTimeout(Duration.ofSeconds(3));
        properties.setIssuerCertPem(new String(material.issuerPem()));
        properties.getRetry().setMaxAttempts(0);

        transport = new HttpRevocationTransport(cryptoProperties, properties);
        PkiRevocationMetrics metrics = new PkiRevocationMetrics(new SimpleMeterRegistry());
        CertificateDirectoryResolver resolver = new CertificateDirectoryResolver(
                new TestObjectProvider<>(null), properties, cryptoProperties);
        OcspCertificateStatusChecker ocspChecker = new OcspCertificateStatusChecker(
                transport, properties, metrics, Duration.ofMillis(1000));
        CrlCertificateStatusChecker crlChecker = new CrlCertificateStatusChecker(
                transport, properties, metrics, Duration.ofMillis(1000));
        checker = new DefaultCertificateStatusChecker(resolver, properties, ocspChecker, crlChecker, metrics);

        template = new CertificateStatusTemplate(new PkiClient() {
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
                throw new UnsupportedOperationException();
            }

            @Override
            public CertificateStatusResult checkCertificateStatus(CertificateStatusQuery query) {
                return checker.check(query);
            }
        });
    }

    @AfterEach
    void tearDown() {
        if (transport != null) {
            transport.close();
        }
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void goodToRevokedTransition_overRealHttps() throws Exception {
        PkiClient.CertificateStatusResult good = checker.check(query());
        assertThat(good.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
        assertThat(good.source()).isEqualTo(PkiClient.RevocationSource.OCSP);

        ocspStatus.set(new org.bouncycastle.cert.ocsp.RevokedStatus(
                new Date(System.currentTimeMillis() - 1000), org.bouncycastle.asn1.x509.CRLReason.keyCompromise));

        PkiClient.CertificateStatusResult revoked = checker.check(query());
        assertThat(revoked.revocationState()).isEqualTo(PkiClient.RevocationState.REVOKED);
        assertThat(revoked.source()).isEqualTo(PkiClient.RevocationSource.OCSP);
    }

    @Test
    void ocspUnavailable_fallsBackToCrlRevoked() throws Exception {
        ocspFails.set(true);
        crlRevoked.set(true);

        PkiClient.CertificateStatusResult result = checker.check(query());

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.REVOKED);
        assertThat(result.source()).isEqualTo(PkiClient.RevocationSource.CRL);
    }

    @Test
    void templateDelegatesToChecker() throws Exception {
        PkiClient.CertificateStatusResult result = template.checkCertificateStatus(query());

        assertThat(result.revocationState()).isEqualTo(PkiClient.RevocationState.GOOD);
    }

    private PkiClient.CertificateStatusQuery query() throws Exception {
        return new PkiClient.CertificateStatusQuery(
                material.leafCert().getSerialNumber().toString(16), null, material.leafDer(), Instant.now());
    }

    private HttpsServer startServer(KeyPair keyPair, X509Certificate certificate) throws Exception {
        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", keyPair.getPrivate(), password, new Certificate[]{certificate});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        httpsServer.createContext("/ocsp", this::handleOcsp);
        httpsServer.createContext("/crl", this::handleCrl);
        httpsServer.setExecutor(Executors.newCachedThreadPool());
        httpsServer.start();
        return httpsServer;
    }

    private void handleOcsp(HttpExchange exchange) throws java.io.IOException {
        try {
            byte[] requestBody = exchange.getRequestBody().readAllBytes();
            if (ocspFails.get()) {
                exchange.sendResponseHeaders(500, -1);
                exchange.close();
                return;
            }
            TestRevocationMaterial.Material current = materialRef.get();
            byte[] nonce = TestRevocationMaterial.extractNonce(requestBody);
            byte[] response = TestRevocationMaterial.ocspResponse(current, ocspStatus.get(),
                    new Date(System.currentTimeMillis() - 60_000),
                    new Date(System.currentTimeMillis() + 3_600_000),
                    nonce, TestRevocationMaterial.ResponderMode.ISSUER);
            exchange.getResponseHeaders().add("Content-Type", "application/ocsp-response");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        } catch (Exception e) {
            exchange.close();
        }
    }

    private void handleCrl(HttpExchange exchange) throws java.io.IOException {
        try {
            TestRevocationMaterial.Material current = materialRef.get();
            byte[] crl = TestRevocationMaterial.crl(current,
                    crlRevoked.get() ? current.leafCert().getSerialNumber() : null,
                    new Date(System.currentTimeMillis() - 60_000),
                    new Date(System.currentTimeMillis() + 3_600_000), false);
            exchange.getResponseHeaders().add("Content-Type", "application/pkix-crl");
            exchange.sendResponseHeaders(200, crl.length);
            exchange.getResponseBody().write(crl);
            exchange.close();
        } catch (Exception e) {
            exchange.close();
        }
    }
}
