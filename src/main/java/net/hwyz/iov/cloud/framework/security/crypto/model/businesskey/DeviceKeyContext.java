package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;

import java.io.Serializable;

/**
 * 设备维业务密钥寻址上下文（FW-SEC-DSN-CR-009 §4）。
 * <p>
 * 业务目录主键：(deviceSn, bizType/businessDomain, purpose) → active keyId/businessKeyVersion，
 * 权威在 VMD。
 *
 * @param deviceSn 设备 SN
 * @param bizType  业务类型
 * @param purpose  业务用途（可为 null）
 * @param caller   调用方身份（可为 null）
 */
public record DeviceKeyContext(
        String deviceSn,
        BizType bizType,
        String purpose,
        CallerIdentity caller) implements Serializable {
}
