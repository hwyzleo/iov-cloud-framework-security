package net.hwyz.iov.cloud.framework.security.crypto.revocation.config;

import io.micrometer.core.instrument.MeterRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoAutoConfiguration;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.CertificateDirectoryResolver;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.CertificateStatusChecker;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.CertificateStatusTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.CrlCertificateStatusChecker;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.DefaultCertificateStatusChecker;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.HttpRevocationTransport;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.OcspCertificateStatusChecker;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.PkiRevocationHealthIndicator;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.PkiRevocationMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.PkiRevocationProperties;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.RevocationHttpTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * PKI 证书状态/吊销查询自动配置（FW-SEC-DSN-CR-010 §5/§8）
 * <p>
 * 由 {@code crypto.pki.revocation.enabled=true} 条件装配，默认关闭：
 * <ul>
 *   <li>关闭时不创建任何网络客户端、Health 组件与状态检查器，也不影响现有 {@link PkiClient} Bean；</li>
 *   <li>关闭时调用 {@code PkiClient.checkCertificateStatus} 返回明确的 configuration-disabled 异常，不伪造 GOOD。</li>
 * </ul>
 * Actuator 未引入时不创建 Health Bean，其余能力（配置绑定、启动校验、类型化异常、指标）不受影响。
 */
@AutoConfiguration(after = CryptoAutoConfiguration.class)
@EnableConfigurationProperties(PkiRevocationProperties.class)
@ConditionalOnProperty(prefix = "crypto.pki.revocation", name = "enabled", havingValue = "true")
public class PkiRevocationAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(PkiRevocationAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public RevocationHttpTransport revocationHttpTransport(CryptoProperties cryptoProperties,
                                                           PkiRevocationProperties properties) {
        log.info("装配 PKI 吊销查询受管 HTTP 传输: mode={}, totalTimeout={}, redirects={}",
                properties.normalizedMode(), properties.getTotalTimeout(), properties.isRedirectsEnabled());
        return new HttpRevocationTransport(cryptoProperties, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public PkiRevocationMetrics pkiRevocationMetrics(MeterRegistry meterRegistry) {
        return new PkiRevocationMetrics(meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public CertificateDirectoryResolver certificateDirectoryResolver(
            ObjectProvider<PkiClient> pkiClientProvider,
            PkiRevocationProperties properties,
            CryptoProperties cryptoProperties) {
        return new CertificateDirectoryResolver(pkiClientProvider, properties, cryptoProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public OcspCertificateStatusChecker ocspCertificateStatusChecker(RevocationHttpTransport transport,
                                                                     PkiRevocationProperties properties,
                                                                     PkiRevocationMetrics metrics,
                                                                     CryptoProperties cryptoProperties) {
        return new OcspCertificateStatusChecker(transport, properties, metrics, defaultReadTimeout(cryptoProperties));
    }

    @Bean
    @ConditionalOnMissingBean
    public CrlCertificateStatusChecker crlCertificateStatusChecker(RevocationHttpTransport transport,
                                                                   PkiRevocationProperties properties,
                                                                   PkiRevocationMetrics metrics,
                                                                   CryptoProperties cryptoProperties) {
        return new CrlCertificateStatusChecker(transport, properties, metrics, defaultReadTimeout(cryptoProperties));
    }

    @Bean
    @ConditionalOnMissingBean
    public CertificateStatusChecker certificateStatusChecker(CertificateDirectoryResolver resolver,
                                                             PkiRevocationProperties properties,
                                                             OcspCertificateStatusChecker ocspChecker,
                                                             CrlCertificateStatusChecker crlChecker,
                                                             PkiRevocationMetrics metrics) {
        return new DefaultCertificateStatusChecker(resolver, properties, ocspChecker, crlChecker, metrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public CertificateStatusTemplate certificateStatusTemplate(PkiClient pkiClient) {
        return new CertificateStatusTemplate(pkiClient);
    }

    private static Duration defaultReadTimeout(CryptoProperties cryptoProperties) {
        return cryptoProperties.getPki().getReadTimeout() != null
                ? cryptoProperties.getPki().getReadTimeout() : Duration.ofMillis(500);
    }

    /**
     * Actuator 存在时才装配 Health 指标；未引入 Actuator 不影响其余能力。
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(HealthIndicator.class)
    static class HealthConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public PkiRevocationHealthIndicator pkiRevocationHealthIndicator(PkiRevocationProperties properties) {
            String reason = null;
            try {
                DefaultCertificateStatusChecker.validateConfiguration(properties);
            } catch (RuntimeException e) {
                reason = e.getMessage();
                log.error("PKI 吊销查询配置非法，revocation Health=NOT_READY: {}", reason);
            }
            return new PkiRevocationHealthIndicator(properties, reason);
        }
    }
}
