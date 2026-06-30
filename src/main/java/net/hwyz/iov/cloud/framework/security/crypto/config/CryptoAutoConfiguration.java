package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.CryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.client.FeignKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultDeviceResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * 加解密自动配置
 */
@AutoConfiguration
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public EnvelopeCodec envelopeCodec() {
        return new EnvelopeCodec();
    }

    @Bean
    @ConditionalOnMissingBean
    public AeadCipher aeadCipher() {
        return new AeadCipher();
    }

    @Bean
    @ConditionalOnMissingBean
    public KmsClient kmsClient(CryptoProperties properties, FeignKmsClient.KmsFeignClient kmsFeignClient) {
        return new FeignKmsClient(properties, kmsFeignClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public DeviceResolver deviceResolver(CryptoProperties properties) {
        return new DefaultDeviceResolver(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public KeyCache keyCache(CryptoProperties properties, KmsClient kmsClient) {
        return new KeyCache(properties, kmsClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public CryptoMetrics cryptoMetrics(io.micrometer.core.instrument.MeterRegistry meterRegistry) {
        return new CryptoMetrics(meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public CryptoTemplate cryptoTemplate(DeviceResolver deviceResolver, KeyCache keyCache,
                                         AeadCipher aeadCipher, EnvelopeCodec envelopeCodec) {
        return new DefaultCryptoTemplate(deviceResolver, keyCache, aeadCipher, envelopeCodec);
    }
}
