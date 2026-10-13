package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.client.DefaultPkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.config.PkiRevocationAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 吊销查询自动装配测试（FW-SEC-DSN-CR-010 §5/§8）：默认关闭无副作用；启用后装配组件并暴露 Health。
 */
class PkiRevocationAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PkiRevocationAutoConfiguration.class,
                    RefreshAutoConfiguration.class))
            .withBean(CryptoProperties.class)
            .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .withBean(PkiClient.class, DefaultPkiClient::new);

    @Test
    void disabledByDefault_createsNoRevocationComponents() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(CertificateStatusChecker.class);
            assertThat(context).doesNotHaveBean(CertificateStatusTemplate.class);
            assertThat(context).doesNotHaveBean(RevocationHttpTransport.class);
            assertThat(context).doesNotHaveBean(PkiRevocationHealthIndicator.class);

            PkiClient client = context.getBean(PkiClient.class);
            assertThatThrownBy(() -> client.checkCertificateStatus(
                    new PkiClient.CertificateStatusQuery("01", null, null)))
                    .isInstanceOf(CertificateStatusConfigurationException.class);
        });
    }

    @Test
    void enabled_wiresComponentsAndExposesHealth() {
        runner.withPropertyValues("crypto.pki.revocation.enabled=true").run(context -> {
            assertThat(context).hasSingleBean(CertificateStatusChecker.class);
            assertThat(context).hasSingleBean(CertificateStatusTemplate.class);
            assertThat(context).hasSingleBean(RevocationHttpTransport.class);
            assertThat(context).hasSingleBean(PkiRevocationMetrics.class);
            assertThat(context).hasSingleBean(CertificateDirectoryResolver.class);
            assertThat(context).hasSingleBean(OcspCertificateStatusChecker.class);
            assertThat(context).hasSingleBean(CrlCertificateStatusChecker.class);
            assertThat(context).hasSingleBean(PkiRevocationHealthIndicator.class);

            PkiRevocationHealthIndicator health = context.getBean(PkiRevocationHealthIndicator.class);
            assertThat(health.health().getStatus().getCode()).isEqualTo("UP");
        });
    }

    @Test
    void enabledWithInvalidMode_healthIsNotReady() {
        runner.withPropertyValues(
                "crypto.pki.revocation.enabled=true",
                "crypto.pki.revocation.mode=bogus").run(context -> {
            PkiRevocationHealthIndicator health = context.getBean(PkiRevocationHealthIndicator.class);
            assertThat(health.health().getStatus().getCode()).isEqualTo("NOT_READY");
        });
    }
}
