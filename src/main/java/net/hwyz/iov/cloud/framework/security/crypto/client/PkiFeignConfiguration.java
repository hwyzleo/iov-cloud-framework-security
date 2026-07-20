package net.hwyz.iov.cloud.framework.security.crypto.client;

import feign.RequestInterceptor;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * PKI Feign客户端配置
 * 为PKI请求添加认证请求头
 */
public class PkiFeignConfiguration {

    @Bean
    @ConditionalOnProperty(prefix = "crypto.pki", name = "token")
    public RequestInterceptor pkiRequestInterceptor(CryptoProperties properties) {
        return requestTemplate -> {
            String token = properties.getPki().getToken();
            if (token != null && !token.isEmpty()) {
                requestTemplate.header("Authorization", "Bearer " + token);
            }
        };
    }
}
