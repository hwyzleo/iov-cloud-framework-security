package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * 根派生型派生封装结果（FW-SEC-DSN-CR-014 §5.1；承接 FW-SEC-DSN-CR-013 §7.2）。
 * <p>
 * 由 Provider 在受控边界内一次完成「根派生 + 设备证书公钥封装」后返回的<strong>瞬时</strong>结果；
 * framework、VMD、VAGW、TSP 只处理 {@code envelopeBytes} 与非敏感元数据，绝不接收根密钥或派生明文。
 * <p>
 * VMD 只能读取非敏感元数据与<strong>转发</strong> {@code envelopeBytes}；不得解析 ECDH 私密中间状态。
 * 信封 bytes 使用后即释放，不进入日志、指标标签、数据库、Outbox 或消息事件。
 * <p>
 * 相同 operationId + 相同请求摘要重放必须返回<strong>字节级相同</strong>的 {@code envelopeBytes} 与
 * {@code envelopeDigest}（FW-SEC-DSN-CR-014 §5.2/§6）。
 *
 * @param logicalKeyId      逻辑派生实例标识（确定性引用，不等于随机材料对象 ID）
 * @param kmsKeyRef         不透明派生引用（由 Provider 生成，消费者不得解析出锚原文）
 * @param rootKeyVersion    Transit/HSM 根密钥版本
 * @param derivationVersion 派生格式版本（与 rootKeyVersion、businessKeyVersion 分离）
 * @param wrappingSuite     封装套件（首期 EC 为 {@link WrappingSuite#ECDH_ES_P256_HKDF_SHA256_AES256GCM}）
 * @param envelopeBytes     完整自描述信封 canonical bytes（瞬时，转发用，不落库）
 * @param envelopeDigest    信封摘要（SHA-256(canonicalEnvelopeBytesWithoutDigest)）
 * @param kcv               密钥校验值（仅用于导入一致性校验）
 * @param operationId       操作标识（对账主键）
 */
public record DerivedWrappedKey(
        String logicalKeyId,
        String kmsKeyRef,
        long rootKeyVersion,
        String derivationVersion,
        WrappingSuite wrappingSuite,
        byte[] envelopeBytes,
        byte[] envelopeDigest,
        byte[] kcv,
        String operationId) implements java.io.Serializable {

    public DerivedWrappedKey {
        Objects.requireNonNull(wrappingSuite, "wrappingSuite must not be null（无隐式套件推断）");
        envelopeBytes = envelopeBytes == null ? null : envelopeBytes.clone();
        envelopeDigest = envelopeDigest == null ? null : envelopeDigest.clone();
        kcv = kcv == null ? null : kcv.clone();
    }

    @Override
    public byte[] envelopeBytes() {
        return envelopeBytes == null ? null : envelopeBytes.clone();
    }

    @Override
    public byte[] envelopeDigest() {
        return envelopeDigest == null ? null : envelopeDigest.clone();
    }

    @Override
    public byte[] kcv() {
        return kcv == null ? null : kcv.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DerivedWrappedKey that)) {
            return false;
        }
        return rootKeyVersion == that.rootKeyVersion
                && Objects.equals(logicalKeyId, that.logicalKeyId)
                && Objects.equals(kmsKeyRef, that.kmsKeyRef)
                && Objects.equals(derivationVersion, that.derivationVersion)
                && wrappingSuite == that.wrappingSuite
                && Arrays.equals(envelopeBytes, that.envelopeBytes)
                && Arrays.equals(envelopeDigest, that.envelopeDigest)
                && Arrays.equals(kcv, that.kcv)
                && Objects.equals(operationId, that.operationId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(logicalKeyId, kmsKeyRef, rootKeyVersion, derivationVersion,
                wrappingSuite, operationId);
        result = 31 * result + Arrays.hashCode(envelopeBytes);
        result = 31 * result + Arrays.hashCode(envelopeDigest);
        result = 31 * result + Arrays.hashCode(kcv);
        return result;
    }

    /**
     * 非敏感描述：不回显信封与 KCV 内容。
     */
    @Override
    public String toString() {
        return "DerivedWrappedKey{logicalKeyId='" + logicalKeyId + "', kmsKeyRef='" + kmsKeyRef
                + "', rootKeyVersion=" + rootKeyVersion + ", derivationVersion='" + derivationVersion
                + "', wrappingSuite=" + wrappingSuite
                + ", envelopeBytes=" + (envelopeBytes == null ? "null" : "[" + envelopeBytes.length + " bytes]")
                + ", envelopeDigest=" + (envelopeDigest == null ? "null" : "[" + envelopeDigest.length + " bytes]")
                + ", kcv=" + (kcv == null ? "null" : "[" + kcv.length + " bytes]")
                + ", operationId='" + operationId + "'}";
    }
}
