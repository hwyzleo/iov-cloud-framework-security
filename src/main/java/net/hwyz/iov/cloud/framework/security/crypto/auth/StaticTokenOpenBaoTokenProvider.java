package net.hwyz.iov.cloud.framework.security.crypto.auth;

import net.hwyz.iov.cloud.framework.security.crypto.exception.OpenBaoAuthenticationException;

/**
 * 静态 Token 认证实现（FW-SEC-DSN-CR-019 §5.2）。
 * <p>
 * 读取配置的 {@code crypto.kms.token}，保持既有 Feign 通道行为兼容；
 * 仅适用于开发/测试。Token 不支持刷新，{@code invalidateOnUnauthorized} 不做任何事
 * （仍由调用方按一次性失败处理）。生产 Transit 本地 Wrap 应使用 AppRole 实现。
 */
public class StaticTokenOpenBaoTokenProvider implements OpenBaoTokenProvider {

    private final String token;

    public StaticTokenOpenBaoTokenProvider(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("crypto.kms.token must not be blank for static token auth");
        }
        this.token = token;
    }

    @Override
    public String requireValidToken(KmsAuthScope scope) {
        return token;
    }

    @Override
    public void invalidateOnUnauthorized(KmsAuthScope scope) {
        // 静态 Token 无刷新机制：不做任何事，由调用方按一次性认证失败处理
    }
}
