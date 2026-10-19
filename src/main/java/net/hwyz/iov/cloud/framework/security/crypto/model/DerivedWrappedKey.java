package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * 根派生型派生封装结果（FW-SEC-DSN-CR-014 §5.1；FW-SEC-DSN-CR-015 §4.2）。
 * <p>
 * 由 Provider 在受控边界内一次完成「根派生 + 设备证书公钥封装」后返回的<strong>瞬时</strong>结果；
 * framework、VMD、VAGW、TSP 只处理结构化 {@code envelope} 视图与非敏感元数据，
 * 绝不接收根密钥或派生明文。
 * <p>
 * <strong>CR-015 演进</strong>：
 * <ul>
 *   <li>新增结构化、只读、版本化的 {@link DerivedWrappedKeyEnvelopeView} {@code envelope} 组件，
 *       业务消费者应据此读取 ciphertext / ECDH 参数 / digest / KCV，<strong>禁止</strong>解析
 *       {@code envelopeBytes}（RD-015-1/RD-015-3）；</li>
 *   <li>{@code envelopeBytes} 保留用于审计/结果存储兼容，标记为 <em>opaque</em>，不是跨模块解析契约；</li>
 *   <li>{@code envelope == null} 仅表示<strong>旧格式结果</strong>（二进制/源码兼容读取路径），
 *       不代表 ECDH-ES v1 已就绪；</li>
 *   <li>顶层 {@code wrappingSuite}/{@code rootKeyVersion}/{@code derivationVersion}/{@code operationId}/
 *       {@code envelopeDigest}/{@code kcv} 必须与视图一致，不一致则构造失败。</li>
 * </ul>
 * <p>
 * 相同 operationId + 相同请求摘要重放必须返回<strong>字节级相同</strong>的 {@code envelopeBytes} 与
 * {@code envelopeDigest}（FW-SEC-DSN-CR-014 §5.2/§6）。
 *
 * @param logicalKeyId      逻辑派生实例标识（确定性引用，不等于随机材料对象 ID）
 * @param kmsKeyRef         不透明派生引用（由 Provider 生成，消费者不得解析出锚原文）
 * @param rootKeyVersion    Transit/HSM 根密钥版本
 * @param derivationVersion 派生格式版本（与 rootKeyVersion、businessKeyVersion 分离）
 * @param wrappingSuite     封装套件（首期 EC 为 {@link WrappingSuite#ECDH_ES_P256_HKDF_SHA256_AES256GCM}）
 * @param envelope          结构化信封视图（CR-015）；{@code null} 仅表示旧格式结果
 * @param envelopeBytes     完整自描述信封 canonical bytes（瞬时，opaque，转发/结果存储用）
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
        DerivedWrappedKeyEnvelopeView envelope,
        byte[] envelopeBytes,
        byte[] envelopeDigest,
        byte[] kcv,
        String operationId) implements java.io.Serializable {

    public DerivedWrappedKey {
        Objects.requireNonNull(wrappingSuite, "wrappingSuite must not be null（无隐式套件推断）");
        envelopeBytes = envelopeBytes == null ? null : envelopeBytes.clone();
        envelopeDigest = envelopeDigest == null ? null : envelopeDigest.clone();
        kcv = kcv == null ? null : kcv.clone();
        if (envelope != null) {
            requireEnvelopeConsistent(logicalKeyId, rootKeyVersion, derivationVersion, wrappingSuite,
                    envelope, envelopeDigest, kcv, operationId);
        }
    }

    /**
     * 向后兼容构造（CR-015 §8）：不携带结构化视图的旧格式结果（{@code envelope = null}）。
     * <p>
     * 保留本构造函数的 JVM descriptor，使既有消费者（framework/VMD/VAGW/TSP）二进制与源码兼容。
     *
     * @param logicalKeyId      逻辑派生实例标识
     * @param kmsKeyRef         不透明派生引用
     * @param rootKeyVersion    根密钥版本
     * @param derivationVersion 派生格式版本
     * @param wrappingSuite     封装套件
     * @param envelopeBytes     canonical 信封 bytes（opaque）
     * @param envelopeDigest    信封摘要
     * @param kcv               密钥校验值
     * @param operationId       操作标识
     */
    public DerivedWrappedKey(String logicalKeyId, String kmsKeyRef, long rootKeyVersion,
                             String derivationVersion, WrappingSuite wrappingSuite, byte[] envelopeBytes,
                             byte[] envelopeDigest, byte[] kcv, String operationId) {
        this(logicalKeyId, kmsKeyRef, rootKeyVersion, derivationVersion, wrappingSuite, null,
                envelopeBytes, envelopeDigest, kcv, operationId);
    }

    /**
     * 顶层元数据与结构化视图一致性校验（CR-015 §4.2）：不一致直接构造失败。
     */
    private static void requireEnvelopeConsistent(String logicalKeyId, long rootKeyVersion,
                                                  String derivationVersion, WrappingSuite wrappingSuite,
                                                  DerivedWrappedKeyEnvelopeView envelope, byte[] envelopeDigest,
                                                  byte[] kcv, String operationId) {
        if (wrappingSuite != envelope.wrappingSuite()) {
            throw new IllegalArgumentException(
                    "envelope wrappingSuite diverges from top-level wrappingSuite: "
                            + envelope.wrappingSuite() + " != " + wrappingSuite);
        }
        if (envelopeDigest == null || !Arrays.equals(envelopeDigest, envelope.envelopeDigest())) {
            throw new IllegalArgumentException("envelope envelopeDigest diverges from top-level envelopeDigest");
        }
        if (kcv == null || !Arrays.equals(kcv, envelope.keyCheckValue())) {
            throw new IllegalArgumentException("envelope keyCheckValue diverges from top-level kcv");
        }
        if (envelope instanceof EcdhEsP256EnvelopeViewV1 ecdh) {
            if (rootKeyVersion != ecdh.rootKeyVersion()
                    || !Objects.equals(derivationVersion, ecdh.derivationVersion())
                    || !Objects.equals(operationId, ecdh.operationId())
                    || !Objects.equals(logicalKeyId, ecdh.logicalKeyId())) {
                throw new IllegalArgumentException(
                        "envelope view metadata diverges from top-level DerivedWrappedKey "
                                + "(rootKeyVersion/derivationVersion/operationId/logicalKeyId)");
            }
        }
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
                && Objects.equals(envelope, that.envelope)
                && Arrays.equals(envelopeBytes, that.envelopeBytes)
                && Arrays.equals(envelopeDigest, that.envelopeDigest)
                && Arrays.equals(kcv, that.kcv)
                && Objects.equals(operationId, that.operationId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(logicalKeyId, kmsKeyRef, rootKeyVersion, derivationVersion,
                wrappingSuite, envelope, operationId);
        result = 31 * result + Arrays.hashCode(envelopeBytes);
        result = 31 * result + Arrays.hashCode(envelopeDigest);
        result = 31 * result + Arrays.hashCode(kcv);
        return result;
    }

    /**
     * 非敏感描述：不回显信封、结构化视图与 KCV 内容。
     */
    @Override
    public String toString() {
        return "DerivedWrappedKey{logicalKeyId='" + logicalKeyId + "', kmsKeyRef='" + kmsKeyRef
                + "', rootKeyVersion=" + rootKeyVersion + ", derivationVersion='" + derivationVersion
                + "', wrappingSuite=" + wrappingSuite
                + ", envelope=" + (envelope == null ? "null" : envelope.envelopeFormat()
                        + "/v" + envelope.formatVersion())
                + ", envelopeBytes=" + (envelopeBytes == null ? "null" : "[" + envelopeBytes.length + " bytes]")
                + ", envelopeDigest=" + (envelopeDigest == null ? "null" : "[" + envelopeDigest.length + " bytes]")
                + ", kcv=" + (kcv == null ? "null" : "[" + kcv.length + " bytes]")
                + ", operationId='" + operationId + "'}";
    }
}
