package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * 根派生型派生封装结果（FW-SEC-DSN-CR-013 §7.2/§8）。
 * <p>
 * 由 Provider 在受控边界内一次完成「根派生 + 设备证书公钥封装」后返回的<strong>瞬时</strong>结果；
 * framework、VMD、VAGW、TSP 只处理 Wrapped Key 与非敏感元数据，绝不接收根密钥或派生明文。
 * Wrapped Key 使用后即释放，不进入日志、指标标签、数据库、Outbox 或消息事件。
 *
 * @param logicalKeyId      逻辑派生实例标识（确定性引用，不等于随机材料对象 ID）
 * @param kmsKeyRef         不透明派生引用（由 Provider 生成，消费者不得解析出锚原文）
 * @param rootKeyVersion    Transit/HSM 根密钥版本
 * @param derivationVersion 派生格式版本（与 rootKeyVersion、businessKeyVersion 分离）
 * @param wrapped           收方证书公钥封装后的密钥密文（瞬时，不落库）
 * @param wrappingAlgorithm 封装算法（如 RSA-OAEP-SHA256 / ECDH-ES+A256GCM）
 * @param kcv               密钥校验值（十六进制字节），仅用于导入一致性校验
 * @param operationId       客户端生成的 UUIDv7 操作标识（对账主键）
 */
public record DerivedWrappedKey(
        String logicalKeyId,
        String kmsKeyRef,
        Integer rootKeyVersion,
        String derivationVersion,
        byte[] wrapped,
        String wrappingAlgorithm,
        byte[] kcv,
        String operationId) implements java.io.Serializable {

    public DerivedWrappedKey {
        wrapped = wrapped == null ? null : wrapped.clone();
        kcv = kcv == null ? null : kcv.clone();
    }

    @Override
    public byte[] wrapped() {
        return wrapped == null ? null : wrapped.clone();
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
        return Objects.equals(logicalKeyId, that.logicalKeyId)
                && Objects.equals(kmsKeyRef, that.kmsKeyRef)
                && Objects.equals(rootKeyVersion, that.rootKeyVersion)
                && Objects.equals(derivationVersion, that.derivationVersion)
                && Arrays.equals(wrapped, that.wrapped)
                && Objects.equals(wrappingAlgorithm, that.wrappingAlgorithm)
                && Arrays.equals(kcv, that.kcv)
                && Objects.equals(operationId, that.operationId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(logicalKeyId, kmsKeyRef, rootKeyVersion, derivationVersion,
                wrappingAlgorithm, operationId);
        result = 31 * result + Arrays.hashCode(wrapped);
        result = 31 * result + Arrays.hashCode(kcv);
        return result;
    }

    /**
     * 非敏感描述：不回显 Wrapped Key 与 KCV 内容。
     */
    @Override
    public String toString() {
        return "DerivedWrappedKey{logicalKeyId='" + logicalKeyId + "', kmsKeyRef='" + kmsKeyRef
                + "', rootKeyVersion=" + rootKeyVersion + ", derivationVersion='" + derivationVersion
                + "', wrapped=" + (wrapped == null ? "null" : "[" + wrapped.length + " bytes]")
                + ", wrappingAlgorithm='" + wrappingAlgorithm + "'"
                + ", kcv=" + (kcv == null ? "null" : "[" + kcv.length + " bytes]")
                + ", operationId='" + operationId + "'}";
    }
}
