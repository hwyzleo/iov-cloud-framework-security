package net.hwyz.iov.cloud.framework.security.crypto.client;

/**
 * 业务密钥 Provider 操作状态（FW-SEC-DSN-CR-011 §6.5）。
 * <p>
 * 用于结果未知对账：framework 写操作请求已发送但结果无法确认时，Provider 以原 operationId
 * 返回该状态，framework/VMD 据此继续阻断或补齐，绝不推断成功。
 */
public enum KmsOperationState {
    /** 操作已受理但尚未完成 */
    PENDING,
    /** 操作成功，结果引用可用 */
    SUCCEEDED,
    /** 操作明确失败 */
    FAILED,
    /** 结果未知（Provider 自身亦无法确认），继续阻断并告警 */
    UNKNOWN
}
