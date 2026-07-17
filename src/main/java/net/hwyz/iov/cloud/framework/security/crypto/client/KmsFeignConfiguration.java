package net.hwyz.iov.cloud.framework.security.crypto.client;

import feign.RequestInterceptor;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * KMS Feign客户端配置
 * 为OpenBao请求添加X-Vault-Token请求头
 */
public class KmsFeignConfiguration {

    @Bean
    @ConditionalOnProperty(prefix = "crypto.kms", name = "token")
    public RequestInterceptor kmsRequestInterceptor(CryptoProperties properties) {
        return requestTemplate -> {
            String token = properties.getKms().getToken();
            if (token != null && !token.isEmpty()) {
                requestTemplate.header("X-Vault-Token", token);
            }
        };
    }
}
