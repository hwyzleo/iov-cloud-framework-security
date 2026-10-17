package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 无法取得可用证书材料异常（FW-SEC-DSN-CR-012 §6/§7）。
 * <p>
 * 仅提供 fingerprint 而无 DER/SPKI、来源缺失、Provider/目录不可用、材料未签发、
 * 过期/吊销/UNKNOWN、用途不符或信任锚缺失等场景均 fail-closed 抛出本异常；
 * 绝不映射为可封装或明文降级。
 */
public class CertificateMaterialUnavailableException extends CryptoException {

    public CertificateMaterialUnavailableException(String message) {
        super(Reason.CERTIFICATE_MATERIAL_UNAVAILABLE, message);
    }

    public CertificateMaterialUnavailableException(String message, Throwable cause) {
        super(Reason.CERTIFICATE_MATERIAL_UNAVAILABLE, message, cause);
    }
}
