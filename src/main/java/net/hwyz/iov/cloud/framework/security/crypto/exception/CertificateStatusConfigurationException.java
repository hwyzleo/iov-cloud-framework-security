package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 证书状态查询配置非法/未启用异常（FW-SEC-DSN-CR-010 §5/§7/§8）
 * <p>
 * 两种语义：
 * <ul>
 *   <li><b>未启用</b>：{@code crypto.pki.revocation.enabled=false}（默认）时调用新增 API，
 *       抛出本异常，明确表示「configuration-disabled」，严禁伪造 GOOD；</li>
 *   <li><b>配置非法</b>：端点、issuer、信任锚、协议模式、URL 来源或 timeout 关系非法，
 *       启动期或首次调用期抛出，并令 revocation Health 为 NOT_READY。</li>
 * </ul>
 */
public class CertificateStatusConfigurationException extends CryptoException {

    public CertificateStatusConfigurationException(String message) {
        super(Reason.CERTIFICATE_STATUS_CONFIGURATION_INVALID, message);
    }

    public CertificateStatusConfigurationException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_STATUS_CONFIGURATION_INVALID, message, cause);
    }
}
