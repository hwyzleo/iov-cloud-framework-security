package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 吊销查询配置校验与 Health 语义测试（FW-SEC-DSN-CR-010 §5/§8）。
 */
class PkiRevocationConfigurationTest {

    @Test
    void defaults_areValid() {
        assertThatCode(() -> DefaultCertificateStatusChecker.validateConfiguration(new PkiRevocationProperties()))
                .doesNotThrowAnyException();
    }

    @Test
    void invalidMode_isRejected() {
        PkiRevocationProperties properties = new PkiRevocationProperties();
        properties.setMode("ocsp+crl");
        assertThatThrownBy(() -> DefaultCertificateStatusChecker.validateConfiguration(properties))
                .isInstanceOf(CertificateStatusConfigurationException.class)
                .hasMessageContaining("mode");
    }

    @Test
    void invalidNoncePolicy_isRejected() {
        PkiRevocationProperties properties = new PkiRevocationProperties();
        properties.getOcsp().setNoncePolicy("best-effort");
        assertThatThrownBy(() -> DefaultCertificateStatusChecker.validateConfiguration(properties))
                .isInstanceOf(CertificateStatusConfigurationException.class)
                .hasMessageContaining("nonce-policy");
    }

    @Test
    void invalidAuthMode_isRejected() {
        PkiRevocationProperties properties = new PkiRevocationProperties();
        properties.getAuth().setMode("basic");
        assertThatThrownBy(() -> DefaultCertificateStatusChecker.validateConfiguration(properties))
                .isInstanceOf(CertificateStatusConfigurationException.class)
                .hasMessageContaining("auth.mode");
    }

    @Test
    void nonPositiveTotalTimeout_isRejected() {
        PkiRevocationProperties properties = new PkiRevocationProperties();
        properties.setTotalTimeout(Duration.ZERO);
        assertThatThrownBy(() -> DefaultCertificateStatusChecker.validateConfiguration(properties))
                .isInstanceOf(CertificateStatusConfigurationException.class)
                .hasMessageContaining("total-timeout");
    }

    @Test
    void health_isUpWhenEnabledAndValid() {
        PkiRevocationProperties properties = new PkiRevocationProperties();
        properties.setEnabled(true);
        PkiRevocationHealthIndicator indicator = new PkiRevocationHealthIndicator(properties, null);

        assertThat(indicator.health().getStatus().getCode()).isEqualTo("UP");
    }

    @Test
    void health_isNotReadyWhenConfigurationInvalid() {
        PkiRevocationProperties properties = new PkiRevocationProperties();
        properties.setEnabled(true);
        PkiRevocationHealthIndicator indicator = new PkiRevocationHealthIndicator(properties, "bad mode");

        assertThat(indicator.health().getStatus().getCode()).isEqualTo("NOT_READY");
        assertThat(indicator.health().getDetails()).containsEntry("reason", "bad mode");
    }

    @Test
    void health_isUnknownWhenDisabled() {
        PkiRevocationProperties properties = new PkiRevocationProperties();
        PkiRevocationHealthIndicator indicator = new PkiRevocationHealthIndicator(properties, null);

        assertThat(indicator.health().getStatus().getCode()).isEqualTo("UNKNOWN");
    }
}
