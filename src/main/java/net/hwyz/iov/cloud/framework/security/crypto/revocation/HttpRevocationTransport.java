package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertPem;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.ConnectException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 受管有界 HTTP 传输实现（FW-SEC-DSN-CR-010 §4/§6）
 * <ul>
 *   <li>JVM/System 信任库 + {@code crypto.pki.tls.trusted-certs-pem}/{@code trust-store-file} 追加私有 CA；</li>
 *   <li>强制证书链、有效期、SAN/hostname（依赖 JDK HttpClient 默认 endpoint identification），
 *       禁止 trust-all、禁止关闭主机名校验、禁止从响应动态学习信任锚；</li>
 *   <li>标准 OCSP/CRL 默认匿名；受控场景支持 none|bearer|mtls（Bearer/私钥来自受控配置，不打印）；</li>
 *   <li>受管有界线程池与连接池；禁止 {@code new RestTemplate()}、commonPool 阻塞 I/O、无界队列；</li>
 *   <li>重定向默认关闭；开启时仅 HTTPS 且最终 host 必须与原始 host 一致。</li>
 * </ul>
 */
public class HttpRevocationTransport implements RevocationHttpTransport {

    private static final Logger log = LoggerFactory.getLogger(HttpRevocationTransport.class);

    private final HttpClient httpClient;
    private final ThreadPoolExecutor executor;
    private final CryptoProperties.Pki.Tls tls;
    private final PkiRevocationProperties properties;

    public HttpRevocationTransport(CryptoProperties cryptoProperties, PkiRevocationProperties properties) {
        Objects.requireNonNull(cryptoProperties, "cryptoProperties must not be null");
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.tls = cryptoProperties.getPki().getTls();

        Duration connectTimeout = cryptoProperties.getPki().getConnectTimeout() != null
                ? cryptoProperties.getPki().getConnectTimeout() : Duration.ofMillis(250);
        this.executor = new ThreadPoolExecutor(2, 4, 30, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(64), daemonThreadFactory(), new ThreadPoolExecutor.AbortPolicy());

        SSLContext sslContext = buildSslContext(properties.getAuth());
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .sslContext(sslContext)
                .executor(executor)
                .version(HttpClient.Version.HTTP_1_1);
        if (properties.isRedirectsEnabled()) {
            builder.followRedirects(HttpClient.Redirect.NORMAL);
        } else {
            builder.followRedirects(HttpClient.Redirect.NEVER);
        }
        this.httpClient = builder.build();
    }

    @Override
    public Response get(URI uri, Duration readTimeout, String accept) {
        validateUri(uri);
        HttpRequest.Builder request = baseRequest(uri, readTimeout, accept);
        return handle(uri, request.GET().build());
    }

    @Override
    public Response post(URI uri, byte[] body, String contentType, String accept, Duration readTimeout) {
        validateUri(uri);
        HttpRequest.Builder request = baseRequest(uri, readTimeout, accept)
                .header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        return handle(uri, request.build());
    }

    /**
     * 关闭受管线程池（容器销毁时调用）。
     */
    public void close() {
        executor.shutdownNow();
    }

    private HttpRequest.Builder baseRequest(URI uri, Duration readTimeout, String accept) {
        Duration timeout = readTimeout != null && !readTimeout.isZero() && !readTimeout.isNegative()
                ? readTimeout : Duration.ofMillis(500);
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(timeout);
        if (accept != null && !accept.isBlank()) {
            builder.header("Accept", accept);
        }
        PkiRevocationProperties.Auth auth = properties.getAuth();
        if ("bearer".equals(auth.normalizedMode())) {
            if (auth.getBearerToken() == null || auth.getBearerToken().isBlank()) {
                throw new CertificateStatusConfigurationException(
                        "crypto.pki.revocation.auth.mode=bearer requires a bearer-token from a controlled secret");
            }
            builder.header("Authorization", "Bearer " + auth.getBearerToken());
        }
        return builder;
    }

    private Response handle(URI originalUri, HttpRequest request) {
        try {
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() >= 300 && response.statusCode() < 400) {
                throw new RevocationTransportException(RevocationTransportException.Phase.REDIRECT,
                        "Revocation endpoint returned HTTP " + response.statusCode() + " redirect", null);
            }
            validateFinalUri(originalUri, response.uri());
            return new Response(response.statusCode(), response.body(), response.uri());
        } catch (HttpConnectTimeoutException e) {
            throw new RevocationTransportException(RevocationTransportException.Phase.CONNECT,
                    "Connect timed out for revocation endpoint", e);
        } catch (UnknownHostException e) {
            // DNS 失败不重试（FW-SEC-DSN-CR-010 §6）
            throw new RevocationTransportException(RevocationTransportException.Phase.DNS,
                    "DNS resolution failed for revocation endpoint", e);
        } catch (ConnectException e) {
            throw new RevocationTransportException(RevocationTransportException.Phase.CONNECT,
                    "Connection refused/reset during connect for revocation endpoint", e);
        } catch (SSLException e) {
            throw new RevocationTransportException(RevocationTransportException.Phase.TLS,
                    "TLS handshake/validation failed for revocation endpoint", e);
        } catch (HttpTimeoutException e) {
            throw new RevocationTransportException(RevocationTransportException.Phase.READ_TIMEOUT,
                    "Read timed out after request was sent; outcome unknown", e);
        } catch (RejectedExecutionException e) {
            throw new RevocationTransportException(RevocationTransportException.Phase.EXECUTOR_REJECTED,
                    "Revocation transport thread pool rejected the request", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RevocationTransportException(RevocationTransportException.Phase.INTERRUPTED,
                    "Revocation request interrupted; outcome unknown", e);
        } catch (IOException e) {
            throw new RevocationTransportException(RevocationTransportException.Phase.RESET,
                    "Revocation connection failed after send", e);
        }
    }

    private void validateUri(URI uri) {
        if (uri == null) {
            throw new CertificateStatusConfigurationException("Revocation endpoint URI must not be null");
        }
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        if (properties.isAllowHttp() && "http".equalsIgnoreCase(scheme)) {
            log.warn("吊销查询显式允许非 HTTPS 端点（仅开发/测试）: host={}", uri.getHost());
            return;
        }
        throw new CertificateStatusConfigurationException(
                "Revocation endpoint must be HTTPS (http only when crypto.pki.revocation.allow-http=true): "
                        + "scheme=" + scheme);
    }

    private void validateFinalUri(URI originalUri, URI finalUri) {
        if (finalUri == null || finalUri.equals(originalUri)) {
            return;
        }
        if (!"https".equalsIgnoreCase(finalUri.getScheme())) {
            throw new RevocationTransportException(RevocationTransportException.Phase.TLS,
                    "Redirect to non-HTTPS endpoint rejected", null);
        }
        if (!properties.isRedirectsEnabled()
                || !Objects.equals(originalUri.getHost(), finalUri.getHost())) {
            throw new RevocationTransportException(RevocationTransportException.Phase.REDIRECT,
                    "Redirect rejected (disabled or different host)", null);
        }
    }

    private SSLContext buildSslContext(PkiRevocationProperties.Auth auth) {
        try {
            KeyManager[] keyManagers = buildKeyManagers(auth);
            TrustManager[] trustManagers = buildTrustManagers();
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, null);
            return context;
        } catch (CertificateStatusConfigurationException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateStatusConfigurationException("Failed to build revocation TLS context", e);
        }
    }

    private KeyManager[] buildKeyManagers(PkiRevocationProperties.Auth auth) throws Exception {
        if (!"mtls".equals(auth.normalizedMode())) {
            return null;
        }
        if (isBlank(auth.getClientCertPem()) || isBlank(auth.getClientKeyPem())) {
            throw new CertificateStatusConfigurationException(
                    "crypto.pki.revocation.auth.mode=mtls requires client-cert-pem and client-key-pem "
                            + "from controlled secrets (never reuse device private key)");
        }
        X509Certificate clientCert = CertPem.parseCertificate(auth.getClientCertPem());
        PrivateKey clientKey = parsePrivateKey(auth.getClientKeyPem());
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        char[] password = new char[0];
        keyStore.setKeyEntry("revocation-client", clientKey, password,
                new java.security.cert.Certificate[]{clientCert});
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keyStore, password);
        return factory.getKeyManagers();
    }

    private TrustManager[] buildTrustManagers() throws Exception {
        X509TrustManager system = defaultTrustManager();
        if (tls == null || !tls.isConfigured()) {
            return new TrustManager[]{system};
        }
        X509TrustManager appended = appendedTrustManager();
        return new TrustManager[]{new CompositeX509TrustManager(system, appended)};
    }

    private X509TrustManager appendedTrustManager() throws Exception {
        KeyStore trustStore;
        if (!isBlank(tls.getTrustStoreFile())) {
            Path path = Path.of(tls.getTrustStoreFile());
            if (!Files.isReadable(path)) {
                throw new CertificateStatusConfigurationException(
                        "crypto.pki.tls.trust-store-file is not readable: " + path);
            }
            trustStore = KeyStore.getInstance(tls.getTrustStoreType());
            char[] password = tls.getTrustStorePassword() == null
                    ? null : tls.getTrustStorePassword().toCharArray();
            try (InputStream in = Files.newInputStream(path)) {
                trustStore.load(in, password);
            }
        } else {
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            int index = 0;
            for (byte[] der : CertPem.parsePemBundle(tls.getTrustedCertsPem())) {
                X509Certificate cert = (X509Certificate) factory.generateCertificate(
                        new java.io.ByteArrayInputStream(der));
                trustStore.setCertificateEntry("revocation-trust-" + (index++), cert);
            }
        }
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trustStore);
        return firstX509(factory.getTrustManagers());
    }

    private X509TrustManager defaultTrustManager() throws Exception {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        return firstX509(factory.getTrustManagers());
    }

    private static X509TrustManager firstX509(TrustManager[] managers) {
        for (TrustManager manager : managers) {
            if (manager instanceof X509TrustManager x509) {
                return x509;
            }
        }
        throw new CertificateStatusConfigurationException("No X509TrustManager available for revocation transport");
    }

    private static PrivateKey parsePrivateKey(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object object = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            if (object instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            }
            if (object instanceof PrivateKeyInfo privateKeyInfo) {
                return converter.getPrivateKey(privateKeyInfo);
            }
            throw new CertificateStatusConfigurationException(
                    "Unsupported private key format for revocation mTLS (expect PKCS#8 or PEM key pair)");
        } catch (IOException e) {
            throw new CertificateStatusConfigurationException("Failed to parse revocation mTLS private key", e);
        }
    }

    private static ThreadFactory daemonThreadFactory() {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, "pki-revocation-http-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * 组合信任管理器：先系统信任库，未通过再尝试追加的私有 CA（任一通过即信任）。
     * <p>
     * 主机名校验由 HttpClient 默认 endpoint identification 强制，不在此处放宽。
     */
    static final class CompositeX509TrustManager implements X509TrustManager {

        private final X509TrustManager primary;
        private final X509TrustManager secondary;

        CompositeX509TrustManager(X509TrustManager primary, X509TrustManager secondary) {
            this.primary = primary;
            this.secondary = secondary;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            primary.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                primary.checkServerTrusted(chain, authType);
            } catch (CertificateException primaryFailure) {
                try {
                    secondary.checkServerTrusted(chain, authType);
                } catch (CertificateException secondaryFailure) {
                    secondaryFailure.addSuppressed(primaryFailure);
                    throw secondaryFailure;
                }
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            List<X509Certificate> issuers = new ArrayList<>();
            java.util.Collections.addAll(issuers, primary.getAcceptedIssuers());
            java.util.Collections.addAll(issuers, secondary.getAcceptedIssuers());
            return issuers.toArray(new X509Certificate[0]);
        }
    }
}
