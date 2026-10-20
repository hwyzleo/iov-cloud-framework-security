package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 统一 TBOX 设备证书 Profile 策略拒绝原因（FW-SEC-DSN-CR-017 §10）。
 * <p>
 * 稳定、封闭的拒绝原因词汇，供 VMD 等消费方稳定映射；<strong>不得</strong>依赖异常正文解析。
 * 上述拒绝均为<strong>确定性、不可重试</strong>（证书固有属性）。
 * <p>
 * 与错误分类约定：
 * <ul>
 *   <li>解析源、领域目录、OCSP/CRL 或状态依赖暂不可用 → 沿用 {@link CertificateMaterialUnavailableException}（可重试）；</li>
 *   <li>verifier/profile/capability 未装配 → 独立 unavailable 异常（{@link CertificateProfileVerificationUnavailableException}）；</li>
 *   <li>过期/吊销/链不可信等状态类拒绝 → 由 {@link CertificateEvidenceRejectedException} 承载（保持 CR-014/016 既有表面）。</li>
 * </ul>
 */
public enum CertificateProfileRejectReason {

    /** Profile 不允许（未知/未批准 Profile，或证书不符合 Profile 语义） */
    PROFILE_NOT_ALLOWED,

    /** 非终端实体（BasicConstraints CA=true 或未声明 CA=false） */
    NOT_END_ENTITY,

    /** 公钥算法不允许（非 EC） */
    PUBLIC_KEY_ALGORITHM_NOT_ALLOWED,

    /** 曲线不允许（非 NIST P-256） */
    CURVE_NOT_ALLOWED,

    /** KeyUsage 缺少 digitalSignature */
    DIGITAL_SIGNATURE_MISSING,

    /** KeyUsage 缺少 keyAgreement */
    KEY_AGREEMENT_MISSING,

    /** EKU 缺少 clientAuth */
    CLIENT_AUTH_MISSING,

    /** EKU 冲突：包含 anyExtendedKeyUsage、serverAuth 或其他未批准 EKU（v1 allowlist 仅 clientAuth） */
    EKU_POLICY_CONFLICT,

    /** 存在不受支持的未知关键扩展（fail-closed） */
    UNSUPPORTED_CRITICAL_EXTENSION,

    /** 身份绑定无效：subject 为空 / 缺少 CN/UID / 绑定不一致 */
    IDENTITY_BINDING_INVALID,

    /** 证书绑定不匹配：CR-014 信封与 CR-016 验签证书引用/摘要不一致（ECDSA Provider 调用前拒绝） */
    CERTIFICATE_BINDING_MISMATCH,

    /** 状态拒绝（过期/吊销/链不可信等；保留为稳定词汇，供 Profile 路径统一映射） */
    STATUS_REJECTED
}
