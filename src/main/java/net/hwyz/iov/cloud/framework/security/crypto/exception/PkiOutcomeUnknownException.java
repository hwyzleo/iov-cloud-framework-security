package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * PKI 结果未知异常（FW-SEC-DSN-CR-008 §6）
 * <p>
 * 请求已发送至 PKI（如 step-ca /1.0/sign）但响应丢失（超时、连接中断、响应解析失败），
 * 签发结果未知。禁止自动生成新 OTT 重新签发；记录为 UNKNOWN 供运维核对后受控恢复。
 * <p>
 * <b>业务侧适配要求：</b>调用方必须单独捕获本异常并映射为「结果未知/待对账」语义
 * （如 PENDING_RECONCILE），<b>不得</b>落入通用 {@code catch (Exception)} 分支将其误记为
 * 「失败（FAILED）」——FAILED 是可重试终态，UNKNOWN 禁止自动重签，两者语义不同。
 * 重试路径：捕获后应主动重新查询 getStatus(requestId)（仍返回 UNKNOWN），或按运维
 * 受控恢复流程处理。
 */
public class PkiOutcomeUnknownException extends CryptoException {

    public PkiOutcomeUnknownException(String message) {
        super(Reason.PKI_OUTCOME_UNKNOWN, message);
    }

    public PkiOutcomeUnknownException(String message, Throwable cause) {
        super(Reason.PKI_OUTCOME_UNKNOWN, message, cause);
    }
}
