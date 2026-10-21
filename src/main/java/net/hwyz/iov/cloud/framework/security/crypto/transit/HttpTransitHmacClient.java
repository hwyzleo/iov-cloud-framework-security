package net.hwyz.iov.cloud.framework.security.crypto.transit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.hwyz.iov.cloud.framework.security.crypto.auth.KmsAuthScope;
import net.hwyz.iov.cloud.framework.security.crypto.auth.OpenBaoTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;

import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Transit 专用 HTTP 客户端（FW-SEC-DSN-CR-019 §5.2/§7.2）。
 * <p>
 * 首期只允许两个端点：
 * <pre>
 * POST {endpoint}/v1/transit/hmac/{root}/{algorithm}
 * GET  {endpoint}/v1/transit/keys/{root}
 * </pre>
 * <ul>
 *   <li><strong>无任何日志</strong>：不创建 Logger，不记录请求/响应 body，异常不回显 body；</li>
 *   <li>Token 经 {@link OpenBaoTokenProvider} 短期持有并注入 {@code X-Vault-Token}，
 *       绝不进入异常/日志/指标；</li>
 *   <li>401/403 仅使 Token 失效并<strong>重新认证一次</strong>，不扩大权限或无限重试；</li>
 *   <li>HMAC 响应 {@code vault:v1:<base64>} 严格解析，未知版本/非法 Base64 fail-closed；</li>
 *   <li>连接建立前失败（DNS/connect/TLS）在总预算内有限重试（请求未发送）；读超时不自动重试。</li>
 * </ul>
 */
public class HttpTransitHmacClient implements TransitHmacClient {

    /** OpenBao HMAC 响应版本前缀：{@code vault:v1:<base64>} */
    private static final Pattern HMAC_VERSION_PREFIX = Pattern.compile("^vault:v1:(.+)$");

    private final URI endpoint;
    private final String mount;
    private final OpenBaoTokenProvider tokenProvider;
    private final KmsAuthScope authScope;
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final Duration totalTimeout;
    private final int maxAttempts;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public HttpTransitHmacClient(URI endpoint, String mount, OpenBaoTokenProvider tokenProvider,
                                 Duration connectTimeout, Duration readTimeout, Duration totalTimeout) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
        this.mount = normalizeMount(Objects.requireNonNull(mount, "mount must not be null"));
        this.tokenProvider = Objects.requireNonNull(tokenProvider, "tokenProvider must not be null");
        this.authScope = KmsAuthScope.DERIVED_KEY_TRANSIT;
        this.connectTimeout = connectTimeout == null ? Duration.ofMillis(500) : connectTimeout;
        this.readTimeout = readTimeout == null ? Duration.ofSeconds(1) : readTimeout;
        this.totalTimeout = totalTimeout == null ? Duration.ofSeconds(2) : totalTimeout;
        this.maxAttempts = 2;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(this.connectTimeout)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    private static String normalizeMount(String mount) {
        String trimmed = mount.trim();
        return trimmed.startsWith("/") ? trimmed.substring(1) : trimmed;
    }

    @Override
    public TransitHmacResult hmac(String approvedKeyName, String algorithm, byte[] input,
                                  OperationContext operation) {
        Objects.requireNonNull(approvedKeyName, "approvedKeyName must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(input, "input must not be null");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("input", Base64.getEncoder().encodeToString(input));
        URI uri = endpoint.resolve("/v1/" + mount + "/hmac/" + approvedKeyName + "/" + algorithm);
        HttpRequest request = jsonRequest(uri, body);

        int attempt = 1;
        while (true) {
            try {
                HttpResponse<String> response = send(request);
                return handleHmacResponse(response, approvedKeyName);
            } catch (AuthFailureException e) {
                if (attempt == 1) {
                    tokenProvider.invalidateOnUnauthorized(authScope);
                    attempt++;
                    continue; // 重新认证后最多再试一次
                }
                // 重认证后仍 401：认证失败；403：HMAC 路径权限不足
                throw e.status == 403
                        ? TransitException.hmacForbidden(approvedKeyName)
                        : TransitException.authFailed("hmac:" + approvedKeyName);
            } catch (TransitHttpStatusException e) {
                throw mapStatus(e.status, "hmac:" + approvedKeyName);
            } catch (HttpConnectTimeoutException | ConnectException | UnknownHostException e) {
                // 连接建立前失败：请求未发送，总预算内有限重试
                if (attempt < maxAttempts) {
                    attempt++;
                    continue;
                }
                throw TransitException.unavailable("hmac:" + approvedKeyName + " (connect)", e);
            } catch (HttpTimeoutException e) {
                // 读超时：请求已发送，不自动重试（确定性输入可由调用方安全重放）
                throw TransitException.unavailable("hmac:" + approvedKeyName + " (read timeout)", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw TransitException.unavailable("hmac:" + approvedKeyName + " (interrupted)", e);
            } catch (IOException e) {
                throw TransitException.unavailable("hmac:" + approvedKeyName, e);
            }
        }
    }

    @Override
    public TransitKeyMetadata readMetadata(String approvedKeyName) {
        Objects.requireNonNull(approvedKeyName, "approvedKeyName must not be null");
        URI uri = endpoint.resolve("/v1/" + mount + "/keys/" + approvedKeyName);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(readTimeout)
                .GET()
                .build();
        int attempt = 1;
        while (true) {
            try {
                HttpResponse<String> response = send(request);
                return handleMetadataResponse(response, approvedKeyName);
            } catch (AuthFailureException e) {
                if (attempt == 1) {
                    tokenProvider.invalidateOnUnauthorized(authScope);
                    attempt++;
                    continue;
                }
                throw e.status == 403
                        ? TransitException.hmacForbidden(approvedKeyName)
                        : TransitException.authFailed("metadata:" + approvedKeyName);
            } catch (TransitHttpStatusException e) {
                throw mapStatus(e.status, "metadata:" + approvedKeyName);
            } catch (HttpConnectTimeoutException | ConnectException | UnknownHostException e) {
                if (attempt < maxAttempts) {
                    attempt++;
                    continue;
                }
                throw TransitException.unavailable("metadata:" + approvedKeyName + " (connect)", e);
            } catch (HttpTimeoutException e) {
                throw TransitException.unavailable("metadata:" + approvedKeyName + " (read timeout)", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw TransitException.unavailable("metadata:" + approvedKeyName + " (interrupted)", e);
            } catch (IOException e) {
                throw TransitException.unavailable("metadata:" + approvedKeyName, e);
            }
        }
    }

    @Override
    public TransitSystemHealth probeHealth() {
        // OpenBao /v1/sys/health 为公开端点，无需 Token；状态经非 2xx 状态码 + body 表达
        URI uri = endpoint.resolve("/v1/sys/health");
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(readTimeout)
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode root = objectMapper.readTree(response.body());
            boolean initialized = root.path("initialized").asBoolean(false);
            boolean sealed = root.path("sealed").asBoolean(true);
            boolean standby = root.path("standby").asBoolean(false);
            return new TransitSystemHealth(initialized, sealed, standby);
        } catch (HttpConnectTimeoutException | ConnectException | UnknownHostException e) {
            throw TransitException.unavailable("health (connect)", e);
        } catch (HttpTimeoutException e) {
            throw TransitException.unavailable("health (read timeout)", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw TransitException.unavailable("health (interrupted)", e);
        } catch (IOException e) {
            throw TransitException.unavailable("health", e);
        }
    }

    /**
     * 发送请求并注入短期 Token；非 2xx 抛类型化状态异常（由调用方映射稳定 reason）。
     */
    private HttpResponse<String> send(HttpRequest baseRequest) throws IOException, InterruptedException {
        String token = tokenProvider.requireValidToken(authScope);
        HttpRequest.Builder builder = HttpRequest.newBuilder(baseRequest.uri())
                .timeout(baseRequest.timeout().orElse(readTimeout))
                .method(baseRequest.method(),
                        baseRequest.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()));
        baseRequest.headers().map().forEach((name, values) ->
                values.forEach(value -> builder.header(name, value)));
        builder.header("X-Vault-Token", token);
        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        int status = response.statusCode();
        if (status == 401 || status == 403) {
            throw new AuthFailureException(status);
        }
        if (status < 200 || status >= 300) {
            throw new TransitHttpStatusException(status);
        }
        return response;
    }

    /**
     * 非认证 HTTP 状态 → 稳定 reason 映射（FW-SEC-DSN-CR-019 §10）。
     */
    private TransitException mapStatus(int status, String op) {
        switch (status) {
            case 404:
                // 根缺失 → transit/keys/{root} 404；hmac 路径 404 也视为根不存在
                return TransitException.rootNotFound(op);
            case 503:
                // OpenBao sealed / standby 不可用
                return TransitException.sealed(op);
            default:
                if (status >= 500) {
                    return TransitException.unavailable(op + " (http " + status + ")");
                }
                return TransitException.unavailable(op + " (http " + status + ")");
        }
    }

    private HttpRequest jsonRequest(URI uri, Object body) {
        try {
            return HttpRequest.newBuilder(uri)
                    .timeout(readTimeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                    .build();
        } catch (Exception e) {
            throw TransitException.formatInvalid("request build failed: " + e.getMessage());
        }
    }

    private TransitHmacResult handleHmacResponse(HttpResponse<String> response, String rootKeyName) {
        try {
            JsonNode data = objectMapper.readTree(response.body()).path("data");
            String hmac = data.path("hmac").asText(null);
            if (hmac == null || hmac.isBlank()) {
                throw TransitException.formatInvalid("missing data.hmac");
            }
            Matcher matcher = HMAC_VERSION_PREFIX.matcher(hmac.trim());
            if (!matcher.matches()) {
                // 未知版本前缀（如 vault:v2:...）或非标准格式，一律 fail-closed
                throw TransitException.formatInvalid("unknown HMAC version prefix");
            }
            String encoded = matcher.group(1);
            byte[] value;
            try {
                value = Base64.getDecoder().decode(encoded);
            } catch (IllegalArgumentException e) {
                throw TransitException.formatInvalid("HMAC value is not valid Base64");
            }
            return new TransitHmacResult("v1", value, rootKeyName);
        } catch (IOException e) {
            throw TransitException.formatInvalid("HMAC response unparseable");
        }
    }

    private TransitKeyMetadata handleMetadataResponse(HttpResponse<String> response, String rootKeyName) {
        try {
            JsonNode data = objectMapper.readTree(response.body()).path("data");
            String name = data.path("name").asText(rootKeyName);
            String type = data.path("type").asText(null);
            boolean exportable = data.path("exportable").asBoolean(false);
            boolean derived = data.path("derived").asBoolean(false);
            long currentVersion = data.path("current_key_version").asLong(
                    data.path("latest_version").asLong(1));
            long latestVersion = data.path("latest_version").asLong(1);
            long minDecryption = data.path("min_decryption_version").asLong(1);
            return new TransitKeyMetadata(name, type, exportable, derived,
                    currentVersion, latestVersion, minDecryption);
        } catch (IOException e) {
            throw TransitException.formatInvalid("key metadata response unparseable");
        }
    }

    /**
     * 认证失败信号（401/403）：由调用方在重认证一次后映射为稳定 reason。
     */
    private static final class AuthFailureException extends RuntimeException {
        private final int status;

        AuthFailureException(int status) {
            super("http " + status);
            this.status = status;
        }
    }

    /**
     * 非认证 HTTP 状态信号：由调用方映射为稳定 reason（404→ROOT_NOT_FOUND、503→SEALED 等）。
     */
    private static final class TransitHttpStatusException extends RuntimeException {
        private final int status;

        TransitHttpStatusException(int status) {
            super("http " + status);
            this.status = status;
        }
    }
}
