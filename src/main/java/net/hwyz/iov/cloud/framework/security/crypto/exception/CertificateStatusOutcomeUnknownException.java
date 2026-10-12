package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书状态查询结果未知异常（FW-SEC-DSN-CR-010 §6/§7）
 * <p>
 * 请求已发出但无确定响应（读超时、连接中断、响应无法归因）时抛出。禁止在同一调用内自动重试，
 * 禁止伪造 GOOD；消费方必须 fail-closed 并可另行对账。
 * <p>
 * 注意与 {@code RevocationState.UNKNOWN} 的区别：UNKNOWN 是协议明确给出的「状态未知」一等状态；
 * 本异常表示「没有拿到可判定结果」，两者在消费方审计与指标上应分别处理。
 */
public class CertificateStatusOutcomeUnknownException extends CryptoException {

    public CertificateStatusOutcomeUnknownException(String message) {
        super(Reason.CERTIFICATE_STATUS_OUTCOME_UNKNOWN, message);
    }

    public CertificateStatusOutcomeUnknownException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_STATUS_OUTCOME_UNKNOWN, message, cause);
    }
}
