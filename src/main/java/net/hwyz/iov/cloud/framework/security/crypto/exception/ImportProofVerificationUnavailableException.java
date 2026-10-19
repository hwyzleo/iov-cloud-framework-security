package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 导入证明验证能力未装配异常（FW-SEC-DSN-CR-016 §7）。
 * <p>
 * verifier / capability 未装配（{@code crypto.import-proof.enabled=false} 或依赖未就绪）时抛出。
 * 其语义为<strong>能力未就绪</strong>，而非「签名无效」；能力恢复后应使用<strong>原请求</strong>重试
 * （不得因本异常把业务版本置为 ACTIVE）。
 */
public class ImportProofVerificationUnavailableException extends CryptoException {

    public ImportProofVerificationUnavailableException(String message) {
        super(Reason.IMPORT_PROOF_VERIFICATION_UNAVAILABLE, message);
    }

    public ImportProofVerificationUnavailableException(String message, Throwable cause) {
        super(Reason.IMPORT_PROOF_VERIFICATION_UNAVAILABLE, message, cause);
    }
}
