package net.hwyz.iov.cloud.framework.security.crypto.client;

import feign.RequestInterceptor;
import net.hwyz.iov.cloud.framework.security.crypto.auth.KmsAuthScope;
import net.hwyz.iov.cloud.framework.security.crypto.auth.OpenBaoTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;

/**
 * KMS Feign客户端配置
 * <p>
 * 为OpenBao请求添加X-Vault-Token请求头（FW-SEC-DSN-CR-019 §5.2）。
 * 复用中立 {@link OpenBaoTokenProvider} 认证组件（AppRole 短期 Token / 静态 Token 兼容），
 * 不在 Interceptor 内复制 AppRole 逻辑；Token 不进入日志/异常/指标。
 */
public class KmsFeignConfiguration {

    @Bean
    public RequestInterceptor kmsRequestInterceptor(ObjectProvider<OpenBaoTokenProvider> tokenProviderProvider,
                                                    CryptoProperties properties) {
        return requestTemplate -> {
            OpenBaoTokenProvider tokenProvider = tokenProviderProvider.getIfAvailable();
            String token;
            if (tokenProvider != null) {
                token = tokenProvider.requireValidToken(KmsAuthScope.GENERIC);
            } else {
                token = properties.getKms().getToken();
            }
            if (token != null && !token.isEmpty()) {
                requestTemplate.header("X-Vault-Token", token);
            }
        };
    }
}
