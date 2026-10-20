package net.hwyz.iov.cloud.framework.security.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 统一 TBOX 设备证书 Profile 能力自检测试（FW-SEC-DSN-CR-017 §9）。
 */
class KeyprovCertificateProfileCapabilityTest {

    @Test
    void publicApiAvailable_isExposed() {
        assertTrue(KeyprovCertificateProfileCapability.publicApiAvailable(),
                "TboxDeviceCertificateValidator#validate 公开 API 必须可调用");
    }

    @Test
    void selfCheckReady_positiveAndNegativeVectorsPass() {
        assertTrue(KeyprovCertificateProfileCapability.selfCheckReady(),
                "Profile 能力自检须通过：公开 API + 正负向向量（P-256/双 KU/clientAuth/CA=false/"
                        + "关键扩展/身份/leaf DER digest）");
    }

    @Test
    void supports_declaredOnlyWhenAssembled() {
        assertTrue(KeyprovCertificateProfileCapability.supports(
                KeyprovCertificateProfileCapability.TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1, true),
                "装配开启时声明 Profile capability");
        assertFalse(KeyprovCertificateProfileCapability.supports(
                KeyprovCertificateProfileCapability.TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1, false),
                "装配关闭时不声明 capability");
        assertFalse(KeyprovCertificateProfileCapability.supports("UNKNOWN_CAPABILITY", true),
                "未知 capability 不声明");
    }
}
