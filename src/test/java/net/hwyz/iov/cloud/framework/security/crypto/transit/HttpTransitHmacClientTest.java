package net.hwyz.iov.cloud.framework.security.crypto.transit;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import net.hwyz.iov.cloud.framework.security.crypto.auth.KmsAuthScope;
import net.hwyz.iov.cloud.framework.security.crypto.auth.OpenBaoTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitReason;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Transit 专用 HTTP 客户端测试（FW-SEC-DSN-CR-019 §5.2）。
 * <p>
 * 以本地 HTTP 服务模拟 OpenBao：严格 {@code vault:v1:<base64>} 解析、未知格式 fail-closed、
 * 404/403/503/401 状态映射、Token 失效重认证一次。
 */
class HttpTransitHmacClientTest {

    private HttpServer server;
    private URI endpoint;
    private OpenBaoTokenProvider tokenProvider;
    private HttpTransitHmacClient client;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.start();
        endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
        tokenProvider = mock(OpenBaoTokenProvider.class);
        when(tokenProvider.requireValidToken(any())).thenReturn("tok-1");
        client = new HttpTransitHmacClient(endpoint, "transit", tokenProvider,
                Duration.ofMillis(500), Duration.ofSeconds(1), Duration.ofSeconds(2));
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    private void respond(int status, String body) {
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(status, body.getBytes(StandardCharsets.UTF_8).length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        });
    }

    private void respondJson(int status, String json) {
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, json.getBytes(StandardCharsets.UTF_8).length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }
        });
    }

    @Test
    void hmac_success_strictVaultV1Parse() throws Exception {
        byte[] expected = new byte[]{1, 2, 3, 4};
        respondJson(200, "{\"data\":{\"hmac\":\"vault:v1:"
                + Base64.getEncoder().encodeToString(expected) + "\"}}");

        TransitHmacResult result = client.hmac("v2c-comm-root", "sha2-256",
                new byte[]{9}, new OperationContext("op-1", "idem-1"));
        assertEquals("v1", result.hmacVersion());
        assertArrayEquals(expected, result.hmac());
        // Token 注入：X-Vault-Token 头由客户端发送（此处验证无异常即通过）
        assertNotNull(result);
    }

    @Test
    void hmac_unknownVersionPrefix_failClosed() {
        respondJson(200, "{\"data\":{\"hmac\":\"vault:v2:AAAA\"}}");
        TransitException ex = assertThrows(TransitException.class,
                () -> client.hmac("v2c-comm-root", "sha2-256", new byte[]{9},
                        new OperationContext("op-1", "idem-1")));
        assertEquals(TransitReason.DERIVED_KEY_FORMAT_INVALID, ex.transitReason());
    }

    @Test
    void hmac_missingVaultPrefix_failClosed() {
        respondJson(200, "{\"data\":{\"hmac\":\"AAAA\"}}");
        TransitException ex = assertThrows(TransitException.class,
                () -> client.hmac("v2c-comm-root", "sha2-256", new byte[]{9},
                        new OperationContext("op-1", "idem-1")));
        assertEquals(TransitReason.DERIVED_KEY_FORMAT_INVALID, ex.transitReason());
    }

    @Test
    void hmac_invalidBase64_failClosed() {
        respondJson(200, "{\"data\":{\"hmac\":\"vault:v1:!!!not-base64!!!\"}}");
        TransitException ex = assertThrows(TransitException.class,
                () -> client.hmac("v2c-comm-root", "sha2-256", new byte[]{9},
                        new OperationContext("op-1", "idem-1")));
        assertEquals(TransitReason.DERIVED_KEY_FORMAT_INVALID, ex.transitReason());
    }

    @Test
    void hmac_404_mapsRootNotFound() {
        respond(404, "{\"errors\":[\"invalid key\"]}");
        TransitException ex = assertThrows(TransitException.class,
                () -> client.hmac("v2c-comm-root", "sha2-256", new byte[]{9},
                        new OperationContext("op-1", "idem-1")));
        assertEquals(TransitReason.TRANSIT_ROOT_NOT_FOUND, ex.transitReason());
    }

    @Test
    void hmac_503_mapsSealed() {
        respond(503, "{\"errors\":[\"sealed\"]}");
        TransitException ex = assertThrows(TransitException.class,
                () -> client.hmac("v2c-comm-root", "sha2-256", new byte[]{9},
                        new OperationContext("op-1", "idem-1")));
        assertEquals(TransitReason.TRANSIT_SEALED, ex.transitReason());
    }

    @Test
    void hmac_401_reAuthenticateOnce_thenSucceeds() {
        AtomicInteger calls = new AtomicInteger();
        server.createContext("/", exchange -> {
            if (calls.getAndIncrement() == 0) {
                exchange.sendResponseHeaders(401, -1);
                exchange.close();
            } else {
                byte[] body = ("{\"data\":{\"hmac\":\"vault:v1:"
                        + Base64.getEncoder().encodeToString(new byte[]{5, 6}) + "\"}}")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(body);
                }
            }
        });
        // 第一次 token 无效 → 失效；第二次重新认证
        when(tokenProvider.requireValidToken(any()))
                .thenReturn("bad-token").thenReturn("good-token");

        TransitHmacResult result = client.hmac("v2c-comm-root", "sha2-256", new byte[]{9},
                new OperationContext("op-1", "idem-1"));
        assertArrayEquals(new byte[]{5, 6}, result.hmac());
        verify(tokenProvider).invalidateOnUnauthorized(KmsAuthScope.DERIVED_KEY_TRANSIT);
        verify(tokenProvider, times(2)).requireValidToken(KmsAuthScope.DERIVED_KEY_TRANSIT);
    }

    @Test
    void hmac_401_twice_failsAuth() {
        respond(401, "{\"errors\":[\"permission denied\"]}");
        TransitException ex = assertThrows(TransitException.class,
                () -> client.hmac("v2c-comm-root", "sha2-256", new byte[]{9},
                        new OperationContext("op-1", "idem-1")));
        assertEquals(TransitReason.TRANSIT_AUTH_FAILED, ex.transitReason());
        verify(tokenProvider).invalidateOnUnauthorized(any());
    }

    @Test
    void hmac_403_afterReauth_mapsForbidden() {
        respond(403, "{\"errors\":[\"permission denied\"]}");
        TransitException ex = assertThrows(TransitException.class,
                () -> client.hmac("v2c-comm-root", "sha2-256", new byte[]{9},
                        new OperationContext("op-1", "idem-1")));
        assertEquals(TransitReason.TRANSIT_HMAC_FORBIDDEN, ex.transitReason());
        verify(tokenProvider).invalidateOnUnauthorized(any());
    }

    @Test
    void readMetadata_parsesRootMetadata() {
        respondJson(200, "{\"data\":{\"name\":\"v2c-comm-root\",\"type\":\"aes256-gcm96\","
                + "\"exportable\":false,\"derived\":true,\"current_key_version\":3,"
                + "\"latest_version\":3,\"min_decryption_version\":1}}");
        TransitKeyMetadata metadata = client.readMetadata("v2c-comm-root");
        assertEquals("v2c-comm-root", metadata.name());
        assertFalse(metadata.exportable());
        assertTrue(metadata.derived());
        assertEquals(3, metadata.currentKeyVersion());
        assertTrue(metadata.isAesHmacCompatible());
    }

    @Test
    void probeHealth_parsesSystemHealth() {
        respondJson(200, "{\"initialized\":true,\"sealed\":false,\"standby\":false}");
        TransitSystemHealth health = client.probeHealth();
        assertTrue(health.ready());
    }

    @Test
    void probeHealth_sealedBody_reportsNotReady() {
        // OpenBao sealed 时 /sys/health 返回 503 + {"sealed":true}
        respondJson(503, "{\"initialized\":true,\"sealed\":true,\"standby\":false}");
        TransitSystemHealth health = client.probeHealth();
        assertFalse(health.ready());
        assertTrue(health.sealed());
    }
}
