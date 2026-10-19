package net.hwyz.iov.cloud.framework.security.crypto.model.importproof;

/**
 * 导入证明确定性拒绝原因（FW-SEC-DSN-CR-016 §7）。
 * <p>
 * 全部为<strong>不可重试</strong>的确定性拒绝；证书材料/依赖暂不可用<strong>不</strong>使用本枚举，
 * 而是保持 {@code CertificateMaterialUnavailableException} / 依赖不可用语义。
 */
public enum ImportProofRejectReason {
    /** 算法不在首期 allowlist（仅 ECDSA_P256_SHA256_P1363） */
    ALGORITHM_NOT_ALLOWED,
    /** 字段长度非法（proof≠64B、digest≠32B、KCV≠3B 等） */
    INVALID_LENGTH,
    /** 标量越界（r=0、s=0、r≥n、s≥n） */
    INVALID_SCALAR,
    /** high-S 签名（s &gt; n/2） */
    HIGH_S,
    /** 证书策略摘要与期望值不匹配 */
    CERTIFICATE_DIGEST_MISMATCH,
    /** ECDSA-SHA256 验签失败（含字段绑定被篡改） */
    SIGNATURE_INVALID,
    /** 上下文非法（空值、业务域不允许、版本越界、purpose 不合法等） */
    CONTEXT_INVALID
}
