package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.CertEncryptionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.CryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DataKeyDistributionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCertEncryptionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultDataKeyDistributionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultKeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultSigningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.KeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.SigningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.client.DefaultKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.FeignKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsFeignClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultCertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultDeviceResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
    @ConditionalOnProperty(prefix = "crypto.kms", name = "endpoint")
    public KmsClient kmsClient(CryptoProperties properties, KmsFeignClient kmsFeignClient) {
        return new FeignKmsClient(properties, kmsFeignClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public KmsClient defaultKmsClient() {
        return new DefaultKmsClient();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto", name = "envelope-enabled", havingValue = "true", matchIfMissing = true)
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
    @ConditionalOnProperty(prefix = "crypto", name = "envelope-enabled", havingValue = "true", matchIfMissing = true)
    public CryptoTemplate cryptoTemplate(DeviceResolver deviceResolver, KeyCache keyCache,
                                         AeadCipher aeadCipher, EnvelopeCodec envelopeCodec,
                                         CryptoMetrics cryptoMetrics, KmsClient kmsClient) {
        return new DefaultCryptoTemplate(deviceResolver, keyCache, aeadCipher, envelopeCodec,
                cryptoMetrics, kmsClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.provisioning", name = "enabled", havingValue = "true")
    public KeyProvisioningTemplate keyProvisioningTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics,
                                                           CryptoProperties properties,
                                                           ObjectProvider<DeviceResolver> deviceResolverProvider) {
        return new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties,
                deviceResolverProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.key-prov", name = "enabled", havingValue = "true")
    public DataKeyDistributionTemplate dataKeyDistributionTemplate(KmsClient kmsClient,
                                                                     CryptoMetrics cryptoMetrics,
                                                                     ObjectProvider<DeviceResolver> deviceResolverProvider) {
        return new DefaultDataKeyDistributionTemplate(kmsClient, cryptoMetrics,
                deviceResolverProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.signing", name = "enabled", havingValue = "true")
    public SigningTemplate signingTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics) {
        return new DefaultSigningTemplate(kmsClient, cryptoMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public CertResolver certResolver() {
        return new DefaultCertResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.certenc", name = "enabled", havingValue = "true")
    public CertEncryptionTemplate certEncryptionTemplate(CryptoMetrics cryptoMetrics,
                                                          ObjectProvider<CertResolver> certResolverProvider) {
        return new DefaultCertEncryptionTemplate(cryptoMetrics, certResolverProvider.getIfAvailable());
    }
}
