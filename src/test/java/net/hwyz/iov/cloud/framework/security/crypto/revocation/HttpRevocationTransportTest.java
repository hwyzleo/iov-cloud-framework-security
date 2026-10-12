package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import org.junit.jupiter.api.AfterEach;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 受管 HTTP 传输 TLS/重定向边界测试（FW-SEC-DSN-CR-010 §4/§10）。
 * <p>
 * 使用本地 HttpsServer + 测试 CA 签发/过期的服务端证书，验证私有根信任、错误 SAN、
 * 过期服务证书、明文 HTTP 拒绝与重定向边界。
 */
class HttpRevocationTransportTest {

    private final List<HttpsServer> servers = new ArrayList<>();

    @AfterEach
    void tearDown() {
        servers.forEach(server -> server.stop(0));
        servers.clear();
    }

    @Test
    void trustedPrivateCaOverSystemTrust_succeeds() throws Exception {
        TlsServer tls = newTlsServer("localhost", "127.0.0.1",
                new Date(System.currentTimeMillis() - 3600_000),
                new Date(System.currentTimeMillis() + 3600_000));
        int port = startServer(tls, exchange -> respond(exchange, 200, "crl-body".getBytes()));

        HttpRevocationTransport transport = new HttpRevocationTransport(
                cryptoProperties(tls.caCert()), new PkiRevocationProperties());
        try {
            RevocationHttpTransport.Response response = transport.get(
                    URI.create("https://127.0.0.1:" + port + "/crl"), Duration.ofSeconds(3), null);
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(new String(response.body())).isEqualTo("crl-body");
        } finally {
            transport.close();
        }
    }

    @Test
    void untrustedCa_tlsFails() throws Exception {
        TlsServer tls = newTlsServer("localhost", "127.0.0.1",
                new Date(System.currentTimeMillis() - 3600_000),
                new Date(System.currentTimeMillis() + 3600_000));
        int port = startServer(tls, exchange -> respond(exchange, 200, new byte[]{1}));

        HttpRevocationTransport transport = new HttpRevocationTransport(
                new CryptoProperties(), new PkiRevocationProperties());
        try {
            assertThatThrownBy(() -> transport.get(
                    URI.create("https://127.0.0.1:" + port + "/crl"), Duration.ofSeconds(3), null))
                    .isInstanceOf(RevocationTransportException.class)
                    .extracting(e -> ((RevocationTransportException) e).getPhase())
                    .isEqualTo(RevocationTransportException.Phase.TLS);
        } finally {
            transport.close();
        }
    }

    @Test
    void wrongSan_hostnameVerificationFails() throws Exception {
        TlsServer tls = newTlsServer("wrong.host.invalid", null,
                new Date(System.currentTimeMillis() - 3600_000),
                new Date(System.currentTimeMillis() + 3600_000));
        int port = startServer(tls, exchange -> respond(exchange, 200, new byte[]{1}));

        HttpRevocationTransport transport = new HttpRevocationTransport(
                cryptoProperties(tls.caCert()), new PkiRevocationProperties());
        try {
            assertThatThrownBy(() -> transport.get(
                    URI.create("https://127.0.0.1:" + port + "/crl"), Duration.ofSeconds(3), null))
                    .isInstanceOf(RevocationTransportException.class)
                    .extracting(e -> ((RevocationTransportException) e).getPhase())
                    .isEqualTo(RevocationTransportException.Phase.TLS);
        } finally {
            transport.close();
        }
    }

    @Test
    void expiredServerCertificate_tlsFails() throws Exception {
        TlsServer tls = newTlsServer("localhost", "127.0.0.1",
                new Date(System.currentTimeMillis() - 7200_000),
                new Date(System.currentTimeMillis() - 3600_000));
        int port = startServer(tls, exchange -> respond(exchange, 200, new byte[]{1}));

        HttpRevocationTransport transport = new HttpRevocationTransport(
                cryptoProperties(tls.caCert()), new PkiRevocationProperties());
        try {
            assertThatThrownBy(() -> transport.get(
                    URI.create("https://127.0.0.1:" + port + "/crl"), Duration.ofSeconds(3), null))
                    .isInstanceOf(RevocationTransportException.class)
                    .extracting(e -> ((RevocationTransportException) e).getPhase())
                    .isEqualTo(RevocationTransportException.Phase.TLS);
        } finally {
            transport.close();
        }
    }

    @Test
    void plainHttp_isRejected() {
        HttpRevocationTransport transport = new HttpRevocationTransport(
                new CryptoProperties(), new PkiRevocationProperties());
        try {
            assertThatThrownBy(() -> transport.get(
                    URI.create("http://127.0.0.1:1/crl"), Duration.ofSeconds(1), null))
                    .isInstanceOf(CertificateStatusConfigurationException.class);
        } finally {
            transport.close();
        }
    }

    @Test
    void redirectWhileDisabled_isRejected() throws Exception {
        TlsServer tls = newTlsServer("localhost", "127.0.0.1",
                new Date(System.currentTimeMillis() - 3600_000),
                new Date(System.currentTimeMillis() + 3600_000));
        int port = startServer(tls, exchange -> {
            exchange.getResponseHeaders().add("Location",
                    "https://127.0.0.1:" + exchange.getLocalAddress().getPort() + "/elsewhere");
            respond(exchange, 302, new byte[0]);
        });

        HttpRevocationTransport transport = new HttpRevocationTransport(
                cryptoProperties(tls.caCert()), new PkiRevocationProperties());
        try {
            assertThatThrownBy(() -> transport.get(
                    URI.create("https://127.0.0.1:" + port + "/crl"), Duration.ofSeconds(3), null))
                    .isInstanceOf(RevocationTransportException.class)
                    .extracting(e -> ((RevocationTransportException) e).getPhase())
                    .isEqualTo(RevocationTransportException.Phase.REDIRECT);
        } finally {
            transport.close();
        }
    }

    private record TlsServer(KeyPair serverKeyPair, X509Certificate serverCert, X509Certificate caCert) {
    }

    private TlsServer newTlsServer(String dnsSan, String ipSan, Date notBefore, Date notAfter) throws Exception {
        KeyPair caKeyPair = TestRevocationMaterial.generateKeyPair();
        X509Certificate caCert = TestRevocationMaterial.issueTlsCa(caKeyPair);
        KeyPair serverKeyPair = TestRevocationMaterial.generateKeyPair();
        X509Certificate serverCert = TestRevocationMaterial.issueTlsLeaf(
                caKeyPair, serverKeyPair, dnsSan, ipSan, notBefore, notAfter);
        return new TlsServer(serverKeyPair, serverCert, caCert);
    }

    private CryptoProperties cryptoProperties(X509Certificate trusted) throws Exception {
        CryptoProperties properties = new CryptoProperties();
        properties.getPki().getTls().setTrustedCertsPem(
                TestRevocationMaterial.pem("CERTIFICATE", trusted.getEncoded()));
        return properties;
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpExchange exchange) throws Exception;
    }

    private int startServer(TlsServer tls, Handler handler) throws Exception {
        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", tls.serverKeyPair().getPrivate(), password,
                new Certificate[]{tls.serverCert()});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        server.createContext("/", exchange -> {
            try {
                handler.handle(exchange);
            } catch (Exception e) {
                exchange.close();
            }
        });
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        servers.add(server);
        return server.getAddress().getPort();
    }

    private static void respond(HttpExchange exchange, int status, byte[] body) throws Exception {
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) {
            exchange.getResponseBody().write(body);
        }
        exchange.close();
    }
}
