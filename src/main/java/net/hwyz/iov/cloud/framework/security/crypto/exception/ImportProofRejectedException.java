package net.hwyz.iov.cloud.framework.security.crypto.exception;

import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofRejectReason;

/**
 * 导入证明确定性拒绝异常（FW-SEC-DSN-CR-016 §7）。
 * <p>
 * 表示导入证明在算法、编码、标量/签名或证书摘要绑定等<strong>确定性</strong>维度上被拒绝：
 * 未知算法、长度错误、DER/high-S、r/s 越界、签名不匹配、字段绑定或证书摘要不匹配、上下文非法。
 * 此类失败<strong>不可重试</strong>（{@link #isRetryable()} 恒为 false）。
 * <p>
 * 证书链/KU/Profile/过期/吊销属证书固有属性，保持
 * {@link CertificateEvidenceRejectedException}；证书材料或 OCSP/CRL 暂不可用保持可重试依赖错误；
 * 上述语义<strong>不得</strong>统一包装为本异常，避免把「可重试依赖失败」误判为「签名无效」。
 * <p>
 * 异常消息与 {@link #toString()} <strong>不得</strong>包含 importProof、proofInput、证书 DER、
 * r/s 或完整摘要。
 */
public class ImportProofRejectedException extends CryptoException {

    private final ImportProofRejectReason rejectReason;

    public ImportProofRejectedException(ImportProofRejectReason rejectReason, String message) {
        this(rejectReason, message, null);
    }

    public ImportProofRejectedException(ImportProofRejectReason rejectReason, String message, Throwable cause) {
        super(Reason.IMPORT_PROOF_REJECTED, message, cause);
        this.rejectReason = rejectReason;
    }

    /**
     * 确定性拒绝原因。
     */
    public ImportProofRejectReason rejectReason() {
        return rejectReason;
    }

    /**
     * 导入证明确定性拒绝恒不可重试。
     */
    @Override
    public boolean isRetryable() {
        return false;
    }
}
