package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * PkiClient 证书状态查询 API 契约测试（FW-SEC-DSN-CR-010 §2）。
 */
class PkiClientCertificateStatusApiTest {

    @Test
    void canonicalSerial_normalizesColonsPrefixLeadingZerosAndCase() {
        assertThat(PkiClient.canonicalSerial("0x12:34:AB")).isEqualTo("1234ab");
        assertThat(PkiClient.canonicalSerial("0000FF")).isEqualTo("ff");
        assertThat(PkiClient.canonicalSerial(" 12 34 ")).isEqualTo("1234");
        assertThat(PkiClient.canonicalSerial("0")).isEqualTo("0");
    }

    @Test
    void canonicalSerial_rejectsBlankAndNonHex() {
        assertThatThrownBy(() -> PkiClient.canonicalSerial(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PkiClient.canonicalSerial("  ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PkiClient.canonicalSerial("zzzz")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void query_normalizesSerialAndFingerprintDefaultsDecisionAtAndClonesLeaf() {
        byte[] leaf = {1, 2, 3};
        PkiClient.CertificateStatusQuery query = new PkiClient.CertificateStatusQuery(
                "0xAB:CD", "AA:BB:CC", leaf, null);

        assertThat(query.serial()).isEqualTo("abcd");
        assertThat(query.sha256Fingerprint()).isEqualTo("aabbcc");
        assertThat(query.decisionAt()).isNotNull();

        leaf[0] = 9;
        assertThat(query.leafCertificateDer()).containsExactly(1, 2, 3);
        byte[] returned = query.leafCertificateDer();
        returned[0] = 7;
        assertThat(query.leafCertificateDer()).containsExactly(1, 2, 3);
    }

    @Test
    void query_fingerprintBlank_isNormalizedToNull() {
        PkiClient.CertificateStatusQuery query = new PkiClient.CertificateStatusQuery(
                "01", "  ", null, Instant.parse("2026-10-12T00:00:00Z"));
        assertThat(query.sha256Fingerprint()).isNull();
        assertThat(query.leafCertificateDer()).isNull();
    }

    @Test
    void defaultClient_disabled_throwsConfigurationDisabled_notGood() {
        DefaultPkiClient client = new DefaultPkiClient();
        assertThatThrownBy(() -> client.checkCertificateStatus(
                new PkiClient.CertificateStatusQuery("01", null, null, null)))
                .isInstanceOf(CertificateStatusConfigurationException.class)
                .hasMessageContaining("disabled");
    }

    @Test
    void revocationState_unknownIsFirstClassNotGood() {
        assertThat(PkiClient.RevocationState.UNKNOWN).isNotEqualTo(PkiClient.RevocationState.GOOD);
        assertThat(PkiClient.RevocationSource.values())
                .containsExactly(PkiClient.RevocationSource.OCSP, PkiClient.RevocationSource.CRL);
    }
}
