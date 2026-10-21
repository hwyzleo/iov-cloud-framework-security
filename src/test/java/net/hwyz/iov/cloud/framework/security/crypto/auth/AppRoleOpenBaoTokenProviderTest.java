package net.hwyz.iov.cloud.framework.security.crypto.auth;

import com.sun.net.httpserver.HttpServer;
import net.hwyz.iov.cloud.framework.security.crypto.exception.OpenBaoAuthenticationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * AppRole 短期 Token 认证实现测试（FW-SEC-DSN-CR-019 §5.2）。
 */
class AppRoleOpenBaoTokenProviderTest {

    private HttpServer server;
    private AppRoleOpenBaoTokenProvider provider;
    private Clock clock;
    private AtomicInteger loginCalls;
    private AtomicReference<String> responseJson;
    private AtomicInteger responseStatus;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
        clock = Clock.fixed(Instant.parse("2026-10-21T00:00:00Z"), ZoneOffset.UTC);
        provider = new AppRoleOpenBaoTokenProvider(endpoint, "role-1", "secret-1",
                Duration.ofSeconds(1), Duration.ofSeconds(30), clock);
        loginCalls = new AtomicInteger();
        responseJson = new AtomicReference<>("{}");
        responseStatus = new AtomicInteger(200);
        server.createContext("/", exchange -> {
            loginCalls.incrementAndGet();
            byte[] body = responseJson.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(responseStatus.get(), body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    private void respond(int status, String json) {
        responseStatus.set(status);
        responseJson.set(json);
    }

    @Test
    void requireValidToken_loginAndCache() {
        respond(200, "{\"auth\":{\"client_token\":\"tok-abc\",\"lease_duration\":120}}");
        assertEquals("tok-abc", provider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT));
        // 缓存命中：不重复登录
        assertEquals("tok-abc", provider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT));
        assertEquals(1, loginCalls.get(), "缓存命中不应重复登录");
    }

    @Test
    void requireValidToken_refreshesBeforeExpiry() {
        respond(200, "{\"auth\":{\"client_token\":\"tok-old\",\"lease_duration\":10}}");
        assertEquals("tok-old", provider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT));
        // 时钟推进超过 TTL（10s - 30s buffer → 立即过期）：重新登录
        respond(200, "{\"auth\":{\"client_token\":\"tok-new\",\"lease_duration\":120}}");
        provider.invalidateOnUnauthorized(KmsAuthScope.DERIVED_KEY_TRANSIT);
        assertEquals("tok-new", provider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT));
        assertEquals(2, loginCalls.get());
    }

    @Test
    void invalidateOnUnauthorized_forcesRelogin() {
        respond(200, "{\"auth\":{\"client_token\":\"tok-1\",\"lease_duration\":120}}");
        assertEquals("tok-1", provider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT));
        respond(200, "{\"auth\":{\"client_token\":\"tok-2\",\"lease_duration\":120}}");
        provider.invalidateOnUnauthorized(KmsAuthScope.DERIVED_KEY_TRANSIT);
        assertEquals("tok-2", provider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT));
        assertEquals(2, loginCalls.get());
    }

    @Test
    void loginRejected_non2xx_throwsAuth() {
        respond(403, "{\"errors\":[\"permission denied\"]}");
        assertThrows(OpenBaoAuthenticationException.class,
                () -> provider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT));
    }

    @Test
    void loginProviderError_5xx_throwsAuth() {
        respond(503, "{\"errors\":[\"sealed\"]}");
        assertThrows(OpenBaoAuthenticationException.class,
                () -> provider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT));
    }

    @Test
    void loginMissingToken_throwsAuth() {
        respond(200, "{\"auth\":{}}");
        assertThrows(OpenBaoAuthenticationException.class,
                () -> provider.requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT));
    }

    @Test
    void missingCredentials_rejected() {
        URI endpoint = URI.create("http://127.0.0.1:1");
        assertThrows(IllegalArgumentException.class,
                () -> new AppRoleOpenBaoTokenProvider(endpoint, "  ", "secret-1",
                        Duration.ofSeconds(1), Duration.ofSeconds(30), clock));
        assertThrows(IllegalArgumentException.class,
                () -> new AppRoleOpenBaoTokenProvider(endpoint, "role-1", null,
                        Duration.ofSeconds(1), Duration.ofSeconds(30), clock));
    }
}
