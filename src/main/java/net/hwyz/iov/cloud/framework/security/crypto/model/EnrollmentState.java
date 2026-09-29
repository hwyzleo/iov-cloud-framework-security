package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 证书注册状态枚举
 */
public enum EnrollmentState {

    /**
     * 提交中（结果存储内部状态，对外映射为 PENDING，FW-SEC-DSN-CR-008 §5.1）
     */
    SUBMITTING,

    /**
     * 已提交，等待处理
     */
    PENDING,

    /**
     * 审批中
     */
    APPROVING,

    /**
     * 处理中
     */
    PROCESSING,

    /**
     * 已签发
     */
    ISSUED,

    /**
     * 已拒绝
     */
    REJECTED,

    /**
     * 失败
     */
    FAILED,

    /**
     * 结果未知（请求已发送但响应丢失；禁止自动重签，FW-SEC-DSN-CR-008 §6）
     */
    UNKNOWN
}
