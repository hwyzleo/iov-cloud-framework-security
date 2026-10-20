package net.hwyz.iov.cloud.framework.security.crypto.model;

import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ValidatedTboxDeviceCertificate 模型测试（FW-SEC-DSN-CR-017 §4 约束）。
 */
class ValidatedTboxDeviceCertificateTest {

    private static PublicKey publicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair().getPublic();
    }

    @Test
    void digest_defensiveCopyOnConstructAndAccess() throws Exception {
        byte[] digest = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
        ValidatedTboxDeviceCertificate validated = new ValidatedTboxDeviceCertificate(
                DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1,
                DeviceCertificateRef.ofSerial("0102"), publicKey(), digest,
                true, true, true, true, Instant.now(), null);

        digest[0] = 99;
        assertNotSame(digest, validated.certificatePolicyDigest(), "构造防御性复制");

        byte[] accessed = validated.certificatePolicyDigest();
        accessed[1] = 98;
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
                validated.certificatePolicyDigest(), "访问返回副本");
    }

    @Test
    void toString_doesNotLeakSensitiveMaterial() throws Exception {
        byte[] digest = new byte[32];
        java.util.Arrays.fill(digest, (byte) 0xAB);
        ValidatedTboxDeviceCertificate validated = new ValidatedTboxDeviceCertificate(
                DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1,
                DeviceCertificateRef.ofSerial("0102"), publicKey(), digest,
                true, true, true, true, Instant.parse("2026-10-20T10:00:00Z"), null);

        String str = validated.toString();
        assertFalse(str.contains("0102"), "toString 不得泄漏 serial");
        assertFalse(str.contains("AB"), "toString 不得泄漏完整摘要");
        assertFalse(str.contains("SunEC"), "toString 不得泄漏公钥编码");
        assertTrue(str.contains("TBOX_DEVICE_ECDH_ES_P256_V1"), "toString 输出 Profile");
    }
}
