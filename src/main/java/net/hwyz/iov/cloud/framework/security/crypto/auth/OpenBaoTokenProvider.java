package net.hwyz.iov.cloud.framework.security.crypto.auth;

import net.hwyz.iov.cloud.framework.security.crypto.exception.OpenBaoAuthenticationException;

/**
 * OpenBao 中立认证接口（FW-SEC-DSN-CR-019 §5.2）。
 * <p>
 * 屏蔽 Token 来源（静态/AppRole/云托管）与生命周期（TTL/续期/并发刷新），
 * 供 {@code HttpTransitHmacClient} 与既有 Feign 通道复用，避免复制 AppRole 逻辑。
 * <p>
 * 契约约束：
 * <ul>
 *   <li>{@code requireValidToken} 返回<strong>当前有效</strong>的短期 Token（必要时按作用域刷新）；</li>
 *   <li>{@code invalidateOnUnauthorized} 仅在 401/403 时使缓存失效，<strong>不得扩大权限</strong>；
 *       调用方随后<strong>最多再重新认证一次</strong>，仍失败即确定性失败，不无限重试；</li>
 *   <li>Token 绝不进入异常、日志、trace、指标或 Health detail。</li>
 * </ul>
 */
public interface OpenBaoTokenProvider {

    /**
     * 返回指定作用域的当前有效 Token。
     *
     * @param scope 认证作用域
     * @return X-Vault-Token 值
     * @throws OpenBaoAuthenticationException 认证不可用/失败
     */
    String requireValidToken(KmsAuthScope scope);

    /**
     * 401/403 时使指定作用域的 Token 缓存失效（下次调用重新认证一次）。
     *
     * @param scope 认证作用域
     */
    void invalidateOnUnauthorized(KmsAuthScope scope);
}
