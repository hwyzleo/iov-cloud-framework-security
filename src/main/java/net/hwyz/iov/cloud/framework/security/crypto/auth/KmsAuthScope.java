package net.hwyz.iov.cloud.framework.security.crypto.auth;

/**
 * OpenBao 认证作用域（FW-SEC-DSN-CR-019 §5.2）。
 * <p>
 * 允许同一 JVM 内为不同能力使用<strong>独立最小权限身份</strong>：Token/Role 的权限范围
 * 不必与随机 business-key Provider 共用。Token 只保存在认证组件内存，不进异常/日志/trace/
 * 指标/Health detail。
 */
public enum KmsAuthScope {

    /**
     * Transit 本地派生（DERIVED_ROOT）：仅允许批准 HMAC 路径与指定根 metadata read。
     */
    DERIVED_KEY_TRANSIT,

    /**
     * 随机业务密钥 Provider（RANDOM_MATERIAL，FW-SEC-DSN-CR-011 §6.5）。
     */
    BUSINESS_KEY_RANDOM,

    /**
     * 通用通道。
     */
    GENERIC
}
