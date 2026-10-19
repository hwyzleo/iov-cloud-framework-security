package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofVerificationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.VerifiedImportProof;

/**
 * 导入证明验证门面（FW-SEC-DSN-CR-016 §3）。
 * <p>
 * 验证 TBOX-SEC 在双用途原子提交后、用设备身份私钥生成的
 * {@code ECDSA_P256_SHA256_P1363} Import Attestation：由 framework 依据结构化字段自行构建
 * canonical proofInput，解析并校验设备证书证据，校验 64 字节 P1363 low-S 签名，并执行
 * <strong>真实 ECDSA-SHA256 验签</strong>。
 * <p>
 * <strong>边界</strong>：
 * <ul>
 *   <li>协议无关，不依赖 PAR-PROTO；调用方（如 VMD Adapter）只把 Proto ACK 映射为 framework 请求模型；</li>
 *   <li>{@code ImportProofCanonical.matches} / 字段绑定校验<strong>不得</strong>替代密码学验签；</li>
 *   <li>验签无副作用，不使用 outcome-unknown 语义；失败不得降级为仅执行字段绑定；</li>
 *   <li>verification 时刻取 framework 受信任时钟，调用方不得指定历史时间绕过证书状态。</li>
 * </ul>
 * <p>
 * 受 {@code crypto.import-proof.enabled} 条件装配；未装配时消费方注入
 * {@code ObjectProvider<ImportProofVerifier>} 自行处理
 * {@code ImportProofVerificationUnavailableException} 或调用 {@link ImportProofCapability}。
 */
public interface ImportProofVerifier {

    /**
     * 验证设备导入证明。
     *
     * @param request 协议无关的验证请求（结构化字段，禁止传入 proofInput）
     * @return 最小非敏感验证结果
     * @throws net.hwyz.iov.cloud.framework.security.crypto.exception.ImportProofRejectedException
     *         确定性拒绝（算法/长度/标量/high-S/证书摘要不匹配/签名无效/上下文非法），不可重试
     * @throws net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceRejectedException
     *         证书策略拒绝（链/KU/Profile/曲线/有效期/吊销），不可重试
     * @throws net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException
     *         证书材料/依赖暂不可用，可重试
     */
    VerifiedImportProof verify(ImportProofVerificationRequest request);
}
