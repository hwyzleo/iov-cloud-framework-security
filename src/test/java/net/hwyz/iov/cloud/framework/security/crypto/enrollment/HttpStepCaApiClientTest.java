package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateApplicationRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HttpStepCaApiClient 单元测试（FW-SEC-DSN-CR-008 §3/§9）
 * <p>
 * 使用真实 HTTPS 服务器（自签名根证书，客户端按根指纹固定信任）验证：
 * /1.0/sign 请求与响应、根指纹固定、异常映射（4xx/5xx/未发送）、禁止 Authorization 头。
 */
class HttpStepCaApiClientTest {

    private TestPkiMaterial.Pki material;
    private HttpsServer server;
    private URI endpoint;
    private String rootFingerprint;

    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicReference<String> lastAuthHeader = new AtomicReference<>("__none__");

    @BeforeEach
    void setUp() throws Exception {
        material = TestPkiMaterial.generate(true, "TBOX-00000000000000000000000000000001");
        rootFingerprint = EnrollmentRecord.fingerprintHex(encoded(material.rootCert()));

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("root", material.rootKeyPair().getPrivate(),
                new char[0], new Certificate[]{material.rootCert()});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), null, null);

        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(ssl));

        server.createContext("/1.0/sign", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            lastBody.set(new String(body, StandardCharsets.UTF_8));
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            lastAuthHeader.set(auth == null ? "__none__" : auth);
            String json = "{\"crt\":" + jsonStr(TestPkiMaterial.pem("CERTIFICATE", encoded(material.leafCert())))
                    + ",\"ca\":" + jsonStr(TestPkiMaterial.pem("CERTIFICATE", encoded(material.intermediateCert())))
                    + ",\"certChain\":" + jsonStr(
                            TestPkiMaterial.pem("CERTIFICATE", encoded(material.intermediateCert()))
                            + TestPkiMaterial.pem("CERTIFICATE", encoded(material.rootCert())))
                    + "}";
            byte[] resp = json.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.close();
        });

        server.createContext("/root/", exchange -> {
            byte[] resp = TestPkiMaterial.pem("CERTIFICATE", encoded(material.rootCert()))
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.close();
        });

        server.start();
        endpoint = URI.create("https://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private HttpStepCaApiClient newClient() {
        return new HttpStepCaApiClient(endpoint, rootFingerprint,
                Duration.ofMillis(500), Duration.ofSeconds(2), 3, Duration.ofMillis(10));
    }

    private static String jsonStr(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n") + "\"";
    }

    private static byte[] encoded(java.security.cert.X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private StepCaApiClient.StepCaSignRequest signRequest() {
        return new StepCaApiClient.StepCaSignRequest(
                new String(material.csrPem(), StandardCharsets.UTF_8),
                "eyJhbGciOiJFUzI1NiJ9.test-token", null, null);
    }

    @Test
    void sign_shouldReturnLeafAndOrderedChain() {
        StepCaApiClient.StepCaSignResponse response = newClient().sign(signRequest());

        assertEquals(TestPkiMaterial.pem("CERTIFICATE", encoded(material.leafCert())).trim(),
                response.leafPem().trim());
        assertEquals(2, response.chainPem().size());
        assertEquals(TestPkiMaterial.pem("CERTIFICATE", encoded(material.intermediateCert())).trim(),
                response.chainPem().get(0).trim());
        assertEquals(TestPkiMaterial.pem("CERTIFICATE", encoded(material.rootCert())).trim(),
                response.chainPem().get(1).trim());
    }

    @Test
    void sign_shouldSendCsrAndOtt_withoutAuthorizationHeader() {
        newClient().sign(signRequest());

        assertTrue(lastBody.get().contains("BEGIN CERTIFICATE REQUEST"));
        assertTrue(lastBody.get().contains("test-token"));
        // step-ca 原生 /1.0/sign 不发送现有 Bearer token（FW-SEC-DSN-CR-008 §3.1）
        assertEquals("__none__", lastAuthHeader.get());
    }

    @Test
    void sign_shouldIncludeNotAfter_whenProvided() {
        StepCaApiClient.StepCaSignRequest request =
                new StepCaApiClient.StepCaSignRequest(
                        new String(material.csrPem(), StandardCharsets.UTF_8), "token",
                        null, "2027-01-01T00:00:00Z");
        newClient().sign(request);
        assertTrue(lastBody.get().contains("2027-01-01T00:00:00Z"));
    }

    @Test
    void getRoot_shouldReturnRootPem() {
        StepCaApiClient.StepCaRootResponse root = newClient().getRoot(rootFingerprint);
        assertEquals(TestPkiMaterial.pem("CERTIFICATE", encoded(material.rootCert())).trim(),
                root.rootPem().trim());
    }

    @Test
    void constructor_shouldRejectWrongRootFingerprint() {
        String wrong = "0".repeat(64);
        assertThrows(IllegalStateException.class,
                () -> new HttpStepCaApiClient(endpoint, wrong,
                        Duration.ofMillis(500), Duration.ofSeconds(2), 1, Duration.ofMillis(10)));
    }

    @Test
    void constructor_shouldRejectHttpScheme() {
        URI httpUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
        assertThrows(IllegalArgumentException.class,
                () -> new HttpStepCaApiClient(httpUri, rootFingerprint,
                        Duration.ofMillis(500), Duration.ofSeconds(2), 1, Duration.ofMillis(10)));
    }

    @Test
    void sign_shouldThrowTypedException_on4xx() throws Exception {
        server.removeContext("/1.0/sign");
        server.createContext("/1.0/sign", exchange -> {
            String resp = "{\"error\":\"provisioner token invalid\"}";
            byte[] bytes = resp.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });

        assertThrows(CertificateApplicationRejectedException.class,
                () -> newClient().sign(signRequest()));
    }

    @Test
    void sign_shouldThrowInvalidRequest_on400() throws Exception {
        server.removeContext("/1.0/sign");
        server.createContext("/1.0/sign", exchange -> {
            String resp = "{\"error\":\"csr invalid\"}";
            byte[] bytes = resp.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(400, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });

        assertThrows(InvalidCertificateRequestException.class,
                () -> newClient().sign(signRequest()));
    }

    @Test
    void sign_shouldThrowUnknown_on5xx() throws Exception {
        server.removeContext("/1.0/sign");
        server.createContext("/1.0/sign", exchange -> {
            String resp = "{\"error\":\"internal\"}";
            byte[] bytes = resp.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(500, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });

        // 5xx：请求已发送、结果不可知 → UNKNOWN，禁止自动重试
        assertThrows(PkiOutcomeUnknownException.class,
                () -> newClient().sign(signRequest()));
    }

    @Test
    void sign_shouldRetryThenFail_whenConnectionNotEstablished() {
        HttpStepCaApiClient client = newClient();
        server.stop(0); // 连接建立失败（请求未发送）→ 按预算重试后抛依赖不可用

        PkiDependencyUnavailableException ex = assertThrows(
                PkiDependencyUnavailableException.class, () -> client.sign(signRequest()));
        assertTrue(ex.getMessage().contains("attempts"));
    }

    @Test
    void sign_shouldNormalize_certChainVariant() throws Exception {
        // 仅 crt + certChain（无 ca 字段）的版本差异
        server.removeContext("/1.0/sign");
        server.createContext("/1.0/sign", exchange -> {
            String json = "{\"crt\":" + jsonStr(TestPkiMaterial.pem("CERTIFICATE", encoded(material.leafCert())))
                    + ",\"certChain\":" + jsonStr(
                            TestPkiMaterial.pem("CERTIFICATE", encoded(material.rootCert()))
                            + TestPkiMaterial.pem("CERTIFICATE", encoded(material.intermediateCert())))
                    + "}";
            byte[] resp = json.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.close();
        });

        StepCaApiClient.StepCaSignResponse response = newClient().sign(signRequest());

        // 即使 certChain 乱序，也归一化为 intermediate → root
        assertEquals(2, response.chainPem().size());
        assertEquals(TestPkiMaterial.pem("CERTIFICATE", encoded(material.intermediateCert())).trim(),
                response.chainPem().get(0).trim());
        assertEquals(TestPkiMaterial.pem("CERTIFICATE", encoded(material.rootCert())).trim(),
                response.chainPem().get(1).trim());
    }

    @Test
    void sign_shouldAccept_caOnlyVariant() throws Exception {
        server.removeContext("/1.0/sign");
        server.createContext("/1.0/sign", exchange -> {
            String json = "{\"crt\":" + jsonStr(TestPkiMaterial.pem("CERTIFICATE", encoded(material.leafCert())))
                    + ",\"ca\":" + jsonStr(TestPkiMaterial.pem("CERTIFICATE", encoded(material.intermediateCert())))
                    + "}";
            byte[] resp = json.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.close();
        });

        StepCaApiClient.StepCaSignResponse response = newClient().sign(signRequest());
        // 仅 ca 时补齐固定根 → 链为 [intermediate, root]
        assertEquals(2, response.chainPem().size());
        assertEquals(TestPkiMaterial.pem("CERTIFICATE", encoded(material.intermediateCert())).trim(),
                response.chainPem().get(0).trim());
        assertEquals(TestPkiMaterial.pem("CERTIFICATE", encoded(material.rootCert())).trim(),
                response.chainPem().get(1).trim());
    }
}
