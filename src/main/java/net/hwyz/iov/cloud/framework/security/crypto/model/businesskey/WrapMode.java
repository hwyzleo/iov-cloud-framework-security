package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

/**
 * 封装模式（FW-SEC-DSN-CR-009 §3）。
 */
public enum WrapMode {
    /** 设备证书公钥封装（首期 keyprov 模式，收方=DeviceCertificate/PublicKey） */
    DEVICE_CERT_PUBLIC_KEY,
    /** 运行期封装（缓存取钥场景，收方=RuntimeIdentity） */
    RUNTIME,
    /** 设备根 KEK 封装（仅显式可信 wrappingKeyRef，收方=DeviceRoot） */
    DEVICE_ROOT_KEK
}
