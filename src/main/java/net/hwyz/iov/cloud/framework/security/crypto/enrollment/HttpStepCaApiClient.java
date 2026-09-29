package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateApplicationRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * step-ca 原生 HTTPS API 客户端（FW-SEC-DSN-CR-008 §3）
 * <p>
 * <ul>
 *   <li>以配置的根 SHA-256 指纹调用 GET /root/{sha} 并校验响应证书指纹；</li>
 *   <li>TLS 客户端信任该根证书（受控 truststore），禁止 trust-all；</li>
 *   <li>POST {endpoint}/1.0/sign 同步签发；</li>
 *   <li>仅对「确认请求尚未发送」的失败（DNS、连接建立、TLS 握手）按预算重试；</li>
 *   <li>请求已发送但响应未知（读超时、连接中断、解析失败）→ {@link PkiOutcomeUnknownException}，禁止自动重试。</li>
 * </ul>
 */
public class HttpStepCaApiClient implements StepCaApiClient {

    private static final Logger log = LoggerFactory.getLogger(HttpStepCaApiClient.class);

    private final URI endpoint;
    private final String rootSha256;
    private final HttpClient httpClient;
    private final X509Certificate rootCertificate;
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final int maxAttempts;
    private final Duration baseBackoff;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public HttpStepCaApiClient(URI endpoint, String rootSha256,
                               Duration connectTimeout, Duration readTimeout,
                               int maxAttempts, Duration baseBackoff) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
        if (!"https".equalsIgnoreCase(endpoint.getScheme())) {
            throw new IllegalArgumentException(
                    "step-ca endpoint must be HTTPS, got: " + endpoint + " (FW-SEC-DSN-CR-008 §2.1)");
        }
        this.rootSha256 = normalizeFingerprint(Objects.requireNonNull(rootSha256, "rootSha256 must not be null"));
        this.connectTimeout = connectTimeout == null ? Duration.ofMillis(500) : connectTimeout;
        this.readTimeout = readTimeout == null ? Duration.ofSeconds(2) : readTimeout;
        this.maxAttempts = maxAttempts <= 0 ? 1 : maxAttempts;
        this.baseBackoff = baseBackoff == null ? Duration.ofMillis(100) : baseBackoff;

        // 1) 启动时调用 GET /root/{sha} 获取并校验根证书（指纹固定）
        X509Certificate root = fetchAndVerifyRoot();
        this.rootCertificate = root;
        // 2) 签发客户端信任该根证书（受控 truststore）
        this.httpClient = HttpClient.newBuilder()
                .sslContext(buildSslContext(root))
                .connectTimeout(this.connectTimeout)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    @Override
    public StepCaSignResponse sign(StepCaSignRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("csr", request.csr());
        body.put("ott", request.ott());
        if (request.notBefore() != null) {
            body.put("notBefore", request.notBefore());
        }
        if (request.notAfter() != null) {
            body.put("notAfter", request.notAfter());
        }

        URI signUri = endpoint.resolve("/1.0/sign");
        HttpRequest httpRequest = HttpRequest.newBuilder(signUri)
                .timeout(readTimeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(toJson(body)))
                .build();

        int attempt = 1;
        while (true) {
            try {
                HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
                return handleSignResponse(response);
            } catch (HttpConnectTimeoutException e) {
                // 连接建立超时：请求尚未发送 → 可重试
                if (retry(attempt, e)) {
                    attempt++;
                    continue;
                }
                throw new PkiDependencyUnavailableException(
                        "step-ca connect timed out after " + maxAttempts + " attempts: " + endpoint, e);
            } catch (UnknownHostException | ConnectException | SSLException e) {
                // DNS / 连接建立 / TLS 握手失败：请求尚未发送 → 可重试
                if (retry(attempt, e)) {
                    attempt++;
                    continue;
                }
                throw new PkiDependencyUnavailableException(
                        "step-ca unreachable (DNS/connect/TLS) after " + maxAttempts + " attempts: " + endpoint, e);
            } catch (HttpTimeoutException e) {
                // 请求已发送但响应超时 → 结果未知，禁止自动重试/重签
                throw new PkiOutcomeUnknownException(
                        "step-ca /1.0/sign request sent but response timed out; outcome unknown", e);
            } catch (IOException e) {
                // 连接中断 / 响应解析失败：请求可能已发送 → 结果未知
                throw new PkiOutcomeUnknownException(
                        "step-ca /1.0/sign connection failed after send; outcome unknown: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new PkiOutcomeUnknownException(
                        "step-ca /1.0/sign interrupted; outcome unknown", e);
            }
        }
    }

    @Override
    public StepCaRootResponse getRoot(String sha256Fingerprint) {
        String fingerprint = normalizeFingerprint(sha256Fingerprint);
        URI rootUri = endpoint.resolve("/root/" + fingerprint);
        HttpRequest request = HttpRequest.newBuilder(rootUri)
                .timeout(readTimeout)
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200 && response.body() != null && !response.body().isBlank()) {
                return new StepCaRootResponse(extractRootPem(response.body()));
            }
            throw new PkiDependencyUnavailableException(
                    "step-ca GET /root/" + fingerprint + " returned HTTP " + response.statusCode());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new PkiDependencyUnavailableException(
                    "Failed to fetch step-ca root certificate: " + endpoint, e);
        }
    }

    /**
     * 提取 /root/{sha} 响应中的根证书 PEM（兼容 JSON 信封 {"ca": ...} 与裸 PEM 两种格式）。
     */
    private String extractRootPem(String body) {
        String trimmed = body.trim();
        if (trimmed.startsWith("{")) {
            try {
                JsonNode node = objectMapper.readTree(trimmed);
                JsonNode ca = node.get("ca");
                if (ca != null && ca.isTextual()) {
                    return ca.asText();
                }
            } catch (Exception e) {
                throw new PkiDependencyUnavailableException(
                        "Failed to parse step-ca /root response JSON", e);
            }
        }
        return trimmed;
    }

    /**
     * 启动引导：以根指纹固定 TLS 服务端证书（禁 trust-all），获取并校验根证书。
     */
    /**
     * 启动引导：获取并校验根证书（FW-SEC-DSN-CR-008 §3.2）。
     * <p>
     * step-ca 的 HTTPS 端点使用独立 TLS 证书（如 Step Online CA，链至中间 CA），并非根证书本身，
     * 因此在尚未持有根证书时无法建立受信 TLS。与官方 {@code step ca bootstrap} 一致：
     * 根证书下载（GET /root/{sha}）使用作用域受限的 TLS 直信，随后对下载到的根证书做
     * <b>指纹固定校验</b>（指纹 != 配置值即拒绝启动）与自签名校验；MITM 无法伪造与配置指纹
     * 一致的根证书。所有后续签发流量仅信任该校验后的根证书（受控 truststore，非 trust-all）。
     */
    private X509Certificate fetchAndVerifyRoot() {
        HttpClient bootstrap = HttpClient.newBuilder()
                .sslContext(buildBootstrapSslContext())
                .connectTimeout(connectTimeout)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        URI rootUri = endpoint.resolve("/root/" + rootSha256);
        HttpRequest request = HttpRequest.newBuilder(rootUri)
                .timeout(readTimeout)
                .GET()
                .build();
        try {
            HttpResponse<String> response = bootstrap.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200 || response.body() == null || response.body().isBlank()) {
                throw new IllegalStateException(
                        "step-ca GET /root/" + rootSha256 + " returned HTTP " + response.statusCode()
                                + " at startup; cannot establish trust anchor");
            }
            X509Certificate root = CertPem.parseCertificate(extractRootPem(response.body()));
            String actualFingerprint = EnrollmentRecord.fingerprintHex(encoded(root));
            if (!actualFingerprint.equalsIgnoreCase(rootSha256)) {
                throw new IllegalStateException(
                        "step-ca root fingerprint mismatch: configured=" + rootSha256
                                + " actual=" + actualFingerprint);
            }
            // 根证书必须自签名
            try {
                root.verify(root.getPublicKey());
            } catch (Exception e) {
                throw new IllegalStateException("step-ca root certificate is not self-signed", e);
            }
            log.info("step-ca 根证书已获取并校验: fingerprint={}..{}", rootSha256.substring(0, 8),
                    rootSha256.substring(rootSha256.length() - 8));
            return root;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("Failed to bootstrap step-ca trust anchor from " + endpoint, e);
        }
    }

    private StepCaSignResponse handleSignResponse(HttpResponse<String> response) {
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            return parseSignResponse(response.body());
        }
        if (response.statusCode() >= 400 && response.statusCode() < 500) {
            // 鉴权/授权/CSR 错误 → REJECTED 或类型化异常
            String error = extractError(response.body());
            if (response.statusCode() == 400) {
                throw new InvalidCertificateRequestException("step-ca rejected CSR: " + error);
            }
            throw new CertificateApplicationRejectedException(
                    "step-ca rejected certificate application (HTTP " + response.statusCode() + "): " + error);
        }
        // 5xx：请求已发送、服务端结果不可知 → UNKNOWN，禁止自动重试
        throw new PkiOutcomeUnknownException(
                "step-ca /1.0/sign returned HTTP " + response.statusCode() + "; outcome unknown");
    }

    /**
     * 解析 /1.0/sign 响应，兼容 crt/ca/certChain 版本差异并归一化为确定顺序 leaf → intermediate → root。
     */
    private StepCaSignResponse parseSignResponse(String json) {
        try {
            JsonNode node = objectMapper.readTree(json);
            String crt = text(node, "crt");
            if (crt == null) {
                throw new InvalidCertificateRequestException("step-ca /1.0/sign response missing 'crt'");
            }
            String ca = text(node, "ca");
            String certChain = text(node, "certChain");

            byte[] leafDer = CertPem.derFromPem(crt);
            List<byte[]> candidates = new ArrayList<>();
            if (ca != null && !ca.isBlank()) {
                candidates.addAll(CertPem.parsePemBundle(ca));
            }
            if (certChain != null && !certChain.isBlank()) {
                candidates.addAll(CertPem.parsePemBundle(certChain));
            }
            List<byte[]> chain = orderChain(leafDer, candidates);
            // step-ca /1.0/sign 的 ca/certChain 可能不含根证书：以启动时指纹固定的根补齐，
            // 保证内部输出为确定顺序 leaf → intermediate → root（FW-SEC-DSN-CR-008 §3.1）
            chain = ensureRoot(chain, rootCertificate);
            List<String> chainPem = chain.stream().map(CertPem::toPemCertificate).toList();
            return new StepCaSignResponse(CertPem.toPemCertificate(leafDer), chainPem);
        } catch (InvalidCertificateRequestException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidCertificateRequestException("Failed to parse step-ca /1.0/sign response", e);
        }
    }

    /**
     * 对候选链证书按 leaf 的签发者向上排序（intermediate → root），去重；无法判序时保持输入顺序。
     */
    private List<byte[]> orderChain(byte[] leafDer, List<byte[]> candidates) {
        // 先按指纹去重
        Map<String, byte[]> byFingerprint = new LinkedHashMap<>();
        for (byte[] der : candidates) {
            byFingerprint.putIfAbsent(EnrollmentRecord.fingerprintHex(der), der);
        }
        List<X509Certificate> certs = byFingerprint.values().stream()
                .map(CertPem::parseCertificate)
                .toList();
        X509Certificate leaf = CertPem.parseCertificate(leafDer);
        javax.security.auth.x500.X500Principal issuer = leaf.getIssuerX500Principal();

        List<byte[]> ordered = new ArrayList<>();
        List<X509Certificate> remaining = new ArrayList<>(certs);
        while (!remaining.isEmpty()) {
            X509Certificate next = null;
            for (X509Certificate c : remaining) {
                if (c.getSubjectX500Principal().equals(issuer)) {
                    next = c;
                    break;
                }
            }
            if (next == null) {
                break;
            }
            byte[] der = byFingerprint.get(EnrollmentRecord.fingerprintHex(encoded(next)));
            ordered.add(der);
            remaining.remove(next);
            if (next.getSubjectX500Principal().equals(next.getIssuerX500Principal())) {
                break; // 已到自签名根
            }
            issuer = next.getIssuerX500Principal();
        }
        for (X509Certificate c : remaining) {
            ordered.add(byFingerprint.get(EnrollmentRecord.fingerprintHex(encoded(c))));
        }
        return ordered;
    }

    /**
     * 若链尾证书由固定根签发且链不含根，则追加固定根证书，形成 leaf → intermediate → root。
     */
    private List<byte[]> ensureRoot(List<byte[]> chain, X509Certificate pinnedRoot) {
        if (chain.isEmpty()) {
            return List.of(encoded(pinnedRoot));
        }
        X509Certificate last = CertPem.parseCertificate(chain.get(chain.size() - 1));
        if (last.getSubjectX500Principal().equals(last.getIssuerX500Principal())) {
            return chain; // 已以自签名根结尾
        }
        if (last.getIssuerX500Principal().equals(pinnedRoot.getSubjectX500Principal())) {
            List<byte[]> result = new ArrayList<>(chain);
            result.add(encoded(pinnedRoot));
            return result;
        }
        return chain; // 无法与固定根衔接，交由校验器判定
    }

    private boolean retry(int attempt, Exception e) {
        if (attempt >= maxAttempts) {
            return false;
        }
        long backoffMillis = baseBackoff.toMillis() * (1L << (attempt - 1));
        log.warn("step-ca 请求尚未发送，准备重试 ({}/{}): {}",
                attempt, maxAttempts, e.getMessage());
        try {
            TimeUnit.MILLISECONDS.sleep(Math.min(backoffMillis, 5000));
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return false;
        }
        return true;
    }

    /**
     * 仅用于根证书下载的 TLS 直信上下文（官方 step-cli bootstrap 同款）。
     * 安全由下载后的根证书指纹固定保证，见 {@link #fetchAndVerifyRoot()}。
     */
    private SSLContext buildBootstrapSslContext() {
        try {
            X509TrustManager trustManager = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    // client 证书不做校验（出站客户端）
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // bootstrap 阶段信任服务端证书，随后以根指纹固定下载的根证书
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{trustManager}, new SecureRandom());
            return ctx;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build bootstrap TLS context", e);
        }
    }

    private SSLContext buildSslContext(X509Certificate root) {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("step-ca-root", root);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build step-ca TLS context", e);
        }
    }

    private String toJson(Map<String, Object> body) {
        try {
            return objectMapper.writeValueAsString(body);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize step-ca sign request", e);
        }
    }

    private String extractError(String body) {
        if (body == null || body.isBlank()) {
            return "no error detail";
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode error = node.get("error");
            if (error != null && error.isTextual()) {
                String text = error.asText();
                return text.length() > 200 ? text.substring(0, 200) : text;
            }
        } catch (Exception ignored) {
            // 非 JSON 响应，直接截断
        }
        String trimmed = body.replaceAll("\\s+", " ").trim();
        return trimmed.length() > 200 ? trimmed.substring(0, 200) : trimmed;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }

    private static String normalizeFingerprint(String fingerprint) {
        return fingerprint == null ? null : fingerprint.replace(":", "").toLowerCase();
    }

    private static byte[] encoded(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new InvalidCertificateRequestException("Failed to encode certificate", e);
        }
    }

}
