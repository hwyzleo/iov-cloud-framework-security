package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 证书注册状态枚举
 */
public enum EnrollmentState {

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
    FAILED
}
