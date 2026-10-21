package net.hwyz.iov.cloud.framework.security.crypto.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.OpenBaoAuthenticationException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * AppRole 短期 Token 认证实现（FW-SEC-DSN-CR-019 §5.2）。
 * <p>
 * <ul>
 *   <li>调用 {@code POST {endpoint}/v1/auth/approle/login}（role_id + secret_id）；</li>
 *   <li>Token 只在认证组件内存中缓存，TTL = {@code lease_duration - refreshBuffer}；</li>
 *   <li>到期/失效时单飞（synchronized）重新认证并并发刷新；</li>
 *   <li>{@code invalidateOnUnauthorized} 仅清缓存，不扩大权限；调用方最多再认证一次。</li>
 * </ul>
 * RoleID/SecretID 只允许经 Secret 注入（role-id-file/secret-id-file 或环境变量占位符），
 * 不写入日志、异常、指标或 Health。Token 同理。
 */
public class AppRoleOpenBaoTokenProvider implements OpenBaoTokenProvider {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String LOGIN_PATH = "/v1/auth/approle/login";

    private final URI endpoint;
    private final String roleId;
    private final String secretId;
    private final Duration loginTimeout;
    private final Duration refreshBuffer;
    private final Clock clock;
    private final HttpClient httpClient;

    private volatile CachedToken cache;

    public AppRoleOpenBaoTokenProvider(URI endpoint, String roleId, String secretId,
                                       Duration loginTimeout, Duration refreshBuffer) {
        this(endpoint, roleId, secretId, loginTimeout, refreshBuffer, Clock.systemUTC());
    }

    public AppRoleOpenBaoTokenProvider(URI endpoint, String roleId, String secretId,
                                       Duration loginTimeout, Duration refreshBuffer, Clock clock) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
        if (roleId == null || roleId.isBlank()) {
            throw new IllegalArgumentException("AppRole roleId must not be blank "
                    + "(set crypto.kms.approle.role-id / role-id-file)");
        }
        if (secretId == null || secretId.isBlank()) {
            throw new IllegalArgumentException("AppRole secretId must not be blank "
                    + "(set crypto.kms.approle.secret-id / secret-id-file)");
        }
        this.roleId = roleId;
        this.secretId = secretId;
        this.loginTimeout = loginTimeout == null ? Duration.ofSeconds(1) : loginTimeout;
        this.refreshBuffer = refreshBuffer == null ? Duration.ofSeconds(30) : refreshBuffer;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(this.loginTimeout)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    @Override
    public String requireValidToken(KmsAuthScope scope) {
        CachedToken current = cache;
        if (current != null && current.isValid(clock.instant())) {
            return current.token;
        }
        synchronized (this) {
            current = cache;
            if (current != null && current.isValid(clock.instant())) {
                return current.token;
            }
            CachedToken refreshed = login();
            cache = refreshed;
            return refreshed.token;
        }
    }

    @Override
    public void invalidateOnUnauthorized(KmsAuthScope scope) {
        cache = null;
    }

    /**
     * AppRole 登录；失败抛 {@link OpenBaoAuthenticationException}（消息不含凭据）。
     */
    private CachedToken login() {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("role_id", roleId);
        body.put("secret_id", secretId);
        URI loginUri = endpoint.resolve(LOGIN_PATH);
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder(loginUri)
                    .timeout(loginTimeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            MAPPER.writeValueAsString(body)))
                    .build();
        } catch (Exception e) {
            throw new OpenBaoAuthenticationException("AppRole login request build failed", e);
        }
        try {
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());
            return parseLogin(response);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OpenBaoAuthenticationException("AppRole login interrupted", e);
        } catch (IOException e) {
            throw new OpenBaoAuthenticationException("AppRole login transport failed: " + e.getMessage(), e);
        }
    }

    private CachedToken parseLogin(HttpResponse<String> response) {
        int status = response.statusCode();
        if (status >= 500) {
            throw new OpenBaoAuthenticationException("AppRole login provider unavailable (http " + status + ")");
        }
        if (status < 200 || status >= 300) {
            throw new OpenBaoAuthenticationException("AppRole login rejected (http " + status + ")");
        }
        try {
            JsonNode root = MAPPER.readTree(response.body());
            JsonNode auth = root.path("auth");
            String token = auth.path("client_token").asText(null);
            if (token == null || token.isBlank()) {
                throw new OpenBaoAuthenticationException("AppRole login response missing client_token");
            }
            long leaseDuration = auth.path("lease_duration").asLong(0);
            long ttlSeconds = Math.max(1, leaseDuration - refreshBuffer.getSeconds());
            return new CachedToken(token, clock.instant().plusSeconds(ttlSeconds));
        } catch (IOException e) {
            throw new OpenBaoAuthenticationException("AppRole login response unparseable", e);
        }
    }

    private record CachedToken(String token, Instant expiresAt) {
        boolean isValid(Instant now) {
            return now.isBefore(expiresAt);
        }
    }

    /**
     * 从配置构造：优先 role-id-file/secret-id-file（Secret 挂载），否则内联 role-id/secret-id。
     *
     * @param endpoint   OpenBao 基础地址
     * @param approle    AppRole 配置
     * @param clock      时钟
     * @return 实现实例
     */
    public static AppRoleOpenBaoTokenProvider fromConfig(URI endpoint,
                                                         CryptoProperties.Kms.AppRole approle,
                                                         Clock clock) {
        String roleId = resolveSecret(approle.getRoleId(), approle.getRoleIdFile(), "role-id");
        String secretId = resolveSecret(approle.getSecretId(), approle.getSecretIdFile(), "secret-id");
        return new AppRoleOpenBaoTokenProvider(endpoint, roleId, secretId,
                approle.getLoginTimeout(), approle.getTokenRefreshBuffer(), clock);
    }

    private static String resolveSecret(String inline, String filePath, String name) {
        if (inline != null && !inline.isBlank()) {
            return inline;
        }
        if (filePath != null && !filePath.isBlank()) {
            try {
                byte[] content = Files.readAllBytes(Path.of(filePath));
                return new String(content, StandardCharsets.UTF_8).trim();
            } catch (IOException e) {
                throw new OpenBaoAuthenticationException(
                        "Cannot read AppRole " + name + " secret file: " + filePath, e);
            }
        }
        throw new OpenBaoAuthenticationException("AppRole " + name + " is not configured");
    }
}
