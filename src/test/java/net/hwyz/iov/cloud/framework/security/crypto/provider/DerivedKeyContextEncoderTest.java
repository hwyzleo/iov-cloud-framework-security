package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 派生上下文编码器固定向量（FW-SEC-DSN-CR-019 §6）。
 * <p>
 * {@code context = UTF8("openiov|v2c|{derivationVersion}|{normalizedVIN}|{purpose}")}；
 * 格式、分隔符与大小写形成固定测试向量，UPLINK/DOWNLINK 域隔离。
 */
class DerivedKeyContextEncoderTest {

    private static final String VIN = "LSVAA4187N2123456";

    private final DerivedKeyContextEncoder encoder = new DerivedKeyContextEncoder();
    private final DerivedKeyPolicy v2c = new DerivedKeyPolicyRegistry().policyFor(BizType.V2C_COMM_ROOT);

    @Test
    void v2cUplink_fixedVector() {
        byte[] context = encoder.encode(v2c, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, "v1");
        assertArrayEquals(
                ("openiov|v2c|v1|" + VIN + "|UPLINK_AEAD").getBytes(StandardCharsets.UTF_8),
                context);
    }

    @Test
    void v2cDownlink_domainIsolated() {
        byte[] uplink = encoder.encode(v2c, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, "v1");
        byte[] downlink = encoder.encode(v2c, KeyAnchor.vin(VIN), KeyPurpose.DOWNLINK_AEAD, "v1");
        assertTrue(!java.util.Arrays.equals(uplink, downlink), "UPLINK/DOWNLINK 必须域隔离");
    }

    @Test
    void derivationVersionParticipates() {
        byte[] v1 = encoder.encode(v2c, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, "v1");
        byte[] v2 = encoder.encode(v2c, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, "v2");
        assertTrue(!java.util.Arrays.equals(v1, v2), "派生版本必须参与 context");
    }

    @Test
    void vinNormalizationIsAppliedByAnchor() {
        // KeyAnchor.vin 已规范化（trim + 大写 + 长度/字符集校验），编码器直接用规范化值
        byte[] context = encoder.encode(v2c, KeyAnchor.vin(" " + VIN.toLowerCase() + " "),
                KeyPurpose.UPLINK_AEAD, "v1");
        assertArrayEquals(
                ("openiov|v2c|v1|" + VIN + "|UPLINK_AEAD").getBytes(StandardCharsets.UTF_8),
                context);
    }

    @Test
    void illegalVin_failClosedBeforeEncode() {
        assertThrows(IllegalArgumentException.class, () -> KeyAnchor.vin("BAD-VIN"));
    }

    @Test
    void nullInputs_failFast() {
        assertThrows(NullPointerException.class,
                () -> encoder.encode(null, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, "v1"));
        assertThrows(NullPointerException.class,
                () -> encoder.encode(v2c, null, KeyPurpose.UPLINK_AEAD, "v1"));
        assertThrows(NullPointerException.class,
                () -> encoder.encode(v2c, KeyAnchor.vin(VIN), null, "v1"));
        assertThrows(NullPointerException.class,
                () -> encoder.encode(v2c, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, null));
    }
}
