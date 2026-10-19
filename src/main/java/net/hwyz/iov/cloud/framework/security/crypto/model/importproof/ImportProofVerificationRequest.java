package net.hwyz.iov.cloud.framework.security.crypto.model.importproof;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;

import java.io.Serializable;

/**
 * 导入证明验证请求（FW-SEC-DSN-CR-016 §3）。
 * <p>
 * 协议无关的 framework 自有模型；调用方（如 VMD Adapter）把 Proto ACK 映射为本模型，
 * <strong>不得</strong>传入自称已验证的 proofInput。
 * <p>
 * 约束：
 * <ul>
 *   <li>所有 bytes 防御性复制（构造与访问器均返回副本）；</li>
 *   <li>{@link #toString()} 不输出 proof、证书 DER 或完整摘要；</li>
 *   <li>{@code businessKeyVersion} 为 {@code 1..2^63-1}；</li>
 *   <li>digest=32 字节、KCV=3 字节、proof=64 字节；</li>
 *   <li>验证时刻由 framework 受信任时钟内部取得，<strong>不</strong>由调用方提供。</li>
 * </ul>
 *
 * @param proofAlgorithm            证明算法（首期仅 ECDSA_P256_SHA256_P1363）
 * @param importProof               设备端 64 字节 P1363 low-S 签名
 * @param deviceCertificateRef      本次 provisioning 绑定的 ACTIVE 设备证书引用
 * @param expectedCertificateDigest 期望的 32 字节证书策略摘要
 * @param requestId                 请求标识
 * @param businessDomain            业务域
 * @param purpose                   派生用途
 * @param keyId                     逻辑密钥标识
 * @param businessKeyVersion        VMD 业务版本
 * @param envelopeDigest            信封摘要（32 字节）
 * @param keyCheckValue             密钥校验值（3 字节）
 */
public record ImportProofVerificationRequest(
        ImportProofAlgorithm proofAlgorithm,
        byte[] importProof,
        DeviceCertificateRef deviceCertificateRef,
        byte[] expectedCertificateDigest,
        String requestId,
        String businessDomain,
        KeyPurpose purpose,
        String keyId,
        long businessKeyVersion,
        byte[] envelopeDigest,
        byte[] keyCheckValue
) implements Serializable {

    public ImportProofVerificationRequest {
        importProof = clone(importProof);
        expectedCertificateDigest = clone(expectedCertificateDigest);
        envelopeDigest = clone(envelopeDigest);
        keyCheckValue = clone(keyCheckValue);
    }

    @Override
    public byte[] importProof() {
        return clone(importProof);
    }

    @Override
    public byte[] expectedCertificateDigest() {
        return clone(expectedCertificateDigest);
    }

    @Override
    public byte[] envelopeDigest() {
        return clone(envelopeDigest);
    }

    @Override
    public byte[] keyCheckValue() {
        return clone(keyCheckValue);
    }

    private static byte[] clone(byte[] value) {
        return value == null ? null : value.clone();
    }

    /**
     * 脱敏调试输出：仅含非敏感元数据与字节长度，绝不输出 proof、证书 DER、摘要或 keyId。
     */
    @Override
    public String toString() {
        return "ImportProofVerificationRequest{" +
                "proofAlgorithm=" + proofAlgorithm +
                ", importProofLength=" + length(importProof) +
                ", expectedCertificateDigestLength=" + length(expectedCertificateDigest) +
                ", requestId=" + requestId +
                ", businessDomain=" + businessDomain +
                ", purpose=" + purpose +
                ", businessKeyVersion=" + businessKeyVersion +
                ", envelopeDigestLength=" + length(envelopeDigest) +
                ", keyCheckValueLength=" + length(keyCheckValue) +
                '}';
    }

    private static int length(byte[] value) {
        return value == null ? -1 : value.length;
    }
}
