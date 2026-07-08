package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.io.Serializable;
import java.util.Objects;

/**
 * 收方设备（设备公钥由 KMS 侧按 certSerial / device_sn 解析，本体不出 KMS）
 *
 * @param certSerial 设备证书序列号
 */
public record DeviceRecipient(String certSerial) implements Serializable {
    public DeviceRecipient {
        Objects.requireNonNull(certSerial, "certSerial must not be null");
    }
}
