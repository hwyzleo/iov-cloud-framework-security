package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

/**
 * 导入证明 canonical 输入（FW-SEC-DSN-CR-014 §8）。
 * <p>
 * TBOX SEC/HSM 使用实际导入密钥执行批准的 HMAC/CMAC，或使用批准的设备证明密钥签名，
 * 对如下 canonical 输入产生导入证明（bound to {@code envelopeDigest + KCV}）：
 * <pre>
 * proofInput = lengthPrefixed(
 *   "openiov|keyprov-ack|v1",
 *   requestId,
 *   businessDomain,
 *   purpose,
 *   keyIdDigest,
 *   businessKeyVersion,
 *   envelopeDigest,
 *   kcv
 * )
 * </pre>
 * framework 只提供 canonical builder 与验证工具，<strong>不</strong>持有业务密钥。
 * KCV 仅用于材料一致性校验，不替代 AEAD tag 或设备持钥证明。
 */
public final class ImportProofCanonical {

    /** 导入证明协议标签（首期） */
    public static final String PROOF_LABEL = "openiov|keyprov-ack|v1";

    private ImportProofCanonical() {
    }

    /**
     * 构造导入证明 canonical 输入。
     *
     * @param requestId          请求标识
     * @param businessDomain     业务域
     * @param purpose            派生用途
     * @param keyIdDigest        逻辑密钥标识摘要
     * @param businessKeyVersion VMD 业务版本
     * @param envelopeDigest     信封摘要
     * @param kcv                密钥校验值
     * @return canonical 输入字节
     */
    public static byte[] proofInput(String requestId, String businessDomain, KeyPurpose purpose,
                                    String keyIdDigest, long businessKeyVersion,
                                    byte[] envelopeDigest, byte[] kcv) {
        return CanonicalEncoding.lengthPrefixed(
                CanonicalEncoding.lengthPrefixedUtf8(
                        PROOF_LABEL,
                        requestId,
                        businessDomain,
                        purpose == null ? null : purpose.name(),
                        keyIdDigest,
                        Long.toString(businessKeyVersion)),
                envelopeDigest,
                kcv);
    }

    /**
     * 恒定时间校验导入证明。
     *
     * @param expectedProof 期望证明（framework/对端计算）
     * @param actualProof   实际证明（车端 ACK 携带）
     * @return 一致返回 true
     */
    public static boolean matches(byte[] expectedProof, byte[] actualProof) {
        return CanonicalEncoding.constantTimeEquals(expectedProof, actualProof);
    }
}
