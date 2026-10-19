package net.hwyz.iov.cloud.framework.security.crypto.model.importproof;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

import java.io.Serializable;
import java.time.Instant;

/**
 * 导入证明验证结果（FW-SEC-DSN-CR-016 §3）。
 * <p>
 * 仅包含最小非敏感验证元数据；<strong>不</strong>包含证书私钥、完整证书链、proofInput 原文、
 * importProof 原文或 r/s。所有 bytes 防御性复制；{@link #toString()} 不输出摘要值。
 *
 * @param proofAlgorithm   已验证算法
 * @param certificateDigest 实际证书策略摘要（32 字节；与期望值常量时间匹配后返回）
 * @param purpose          已绑定的派生用途
 * @param proofInputDigest canonical proofInput 的 SHA-256（32 字节，供审计比对）
 * @param verifiedAt       验证时刻（framework 受信任时钟）
 */
public record VerifiedImportProof(
        ImportProofAlgorithm proofAlgorithm,
        byte[] certificateDigest,
        KeyPurpose purpose,
        byte[] proofInputDigest,
        Instant verifiedAt
) implements Serializable {

    public VerifiedImportProof {
        certificateDigest = clone(certificateDigest);
        proofInputDigest = clone(proofInputDigest);
    }

    @Override
    public byte[] certificateDigest() {
        return clone(certificateDigest);
    }

    @Override
    public byte[] proofInputDigest() {
        return clone(proofInputDigest);
    }

    private static byte[] clone(byte[] value) {
        return value == null ? null : value.clone();
    }

    /**
     * 脱敏调试输出：仅含算法、purpose、时间与摘要长度。
     */
    @Override
    public String toString() {
        return "VerifiedImportProof{" +
                "proofAlgorithm=" + proofAlgorithm +
                ", certificateDigestLength=" + (certificateDigest == null ? -1 : certificateDigest.length) +
                ", purpose=" + purpose +
                ", proofInputDigestLength=" + (proofInputDigest == null ? -1 : proofInputDigest.length) +
                ", verifiedAt=" + verifiedAt +
                '}';
    }
}
