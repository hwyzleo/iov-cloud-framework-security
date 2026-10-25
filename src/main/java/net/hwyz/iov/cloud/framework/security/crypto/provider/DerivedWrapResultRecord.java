package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * 派生封装 operation 结果存储记录（FW-SEC-DSN-CR-020 §4；FW-SEC-DSN-CR-014 §6）。
 * <p>
 * 由 {@link OperationResultStore} 持久化的<strong>受控结果</strong>，用于：
 * <ul>
 *   <li>相同 {@code operationId} + 相同请求摘要的字节级幂等重放（重放读取原记录，
 *       <strong>不得</strong>重新调用 encoder、随机源或 Transit，FW-SEC-DSN-CR-020 §4）；</li>
 *   <li>相同 operation 但 profile/请求摘要变化 → 幂等冲突；</li>
 *   <li>PROCESSING/OUTCOME_UNKNOWN 状态下的结果未知对账。</li>
 * </ul>
 * <strong>安全边界</strong>：记录只含非敏感元数据与密文信封参数；<strong>不含</strong>
 * 业务密钥明文、KEK、ECDH shared secret 或临时 EC 私钥（CR-014 §6）。完整密文信封属于
 * 「限定允许」持久化：实现方必须加密存储、最小权限、TTL 与终态清理。
 * <p>
 * {@code aadProfileId == null} 表示<strong>无 profile 的旧格式结果</strong>：只允许按原格式
 * 对账/终结，不得重新编码或升级映射到新 wire（FW-SEC-DSN-CR-020 §6）。
 *
 * @param operationId                操作标识（对账主键）
 * @param requestDigestHex           幂等请求摘要（小写十六进制，FW-SEC-DSN-CR-020 §4）
 * @param aadProfileId               使用的 AAD profile（null = legacy 无 profile）
 * @param status                     结果状态（NEW/PROCESSING/SUCCEEDED/FAILED/OUTCOME_UNKNOWN）
 * @param logicalKeyId               逻辑派生实例标识
 * @param kmsKeyRef                  不透明派生引用
 * @param rootKeyVersion             Transit/HSM 根版本（选定）
 * @param derivationVersion          派生格式版本
 * @param wrappingSuiteWire          封装套件 wire 名称
 * @param envelopeBytes              完整自描述信封 canonical bytes（opaque）
 * @param envelopeDigest             core 信封摘要（SHA-256(canonicalEnvelopeBytesWithoutDigest)）
 * @param kcv                        密钥校验值（3 字节）
 * @param serverEphemeralPublicKey   P-256 ephemeral 公钥（65 字节）
 * @param hkdfSalt                   HKDF salt（32 字节）
 * @param hkdfContextVersion         HKDF info/context 版本
 * @param nonce                      AES-GCM nonce（12 字节）
 * @param ciphertext                 AES-GCM 密文
 * @param authenticationTag          AES-GCM tag（16 字节）
 * @param canonicalAad               实际使用的 canonical AAD 字节（profile 输出或 legacy core AAD）
 * @param aadDigest                  AAD 摘要（SHA-256）
 * @param recipientCertificateFingerprint 收方证书指纹（小写十六进制）
 * @param purpose                    派生用途
 * @param businessKeyVersion         VMD 业务版本
 * @param envelopeOperationId        信封内 operationId（与顶层一致）
 * @param createdAt                  创建时间
 * @param expiresAt                  过期时间（TTL）
 * @param failReason                 终态失败 reason（SUCCEEDED 时 null）
 */
public record DerivedWrapResultRecord(
        String operationId,
        String requestDigestHex,
        String aadProfileId,
        Status status,
        String logicalKeyId,
        String kmsKeyRef,
        long rootKeyVersion,
        String derivationVersion,
        String wrappingSuiteWire,
        byte[] envelopeBytes,
        byte[] envelopeDigest,
        byte[] kcv,
        byte[] serverEphemeralPublicKey,
        byte[] hkdfSalt,
        String hkdfContextVersion,
        byte[] nonce,
        byte[] ciphertext,
        byte[] authenticationTag,
        byte[] canonicalAad,
        byte[] aadDigest,
        String recipientCertificateFingerprint,
        KeyPurpose purpose,
        long businessKeyVersion,
        String envelopeOperationId,
        Instant createdAt,
        Instant expiresAt,
        String failReason) {

    /**
     * 结果状态机（FW-SEC-DSN-CR-014 §6）：
     * NEW → PROCESSING → SUCCEEDED；PROCESSING → FAILED | OUTCOME_UNKNOWN。
     * <p>
     * PROCESSING/OUTCOME_UNKNOWN 不允许新建第二次密码操作。
     */
    public enum Status {
        NEW, PROCESSING, SUCCEEDED, FAILED, OUTCOME_UNKNOWN
    }

    public DerivedWrapResultRecord {
        Objects.requireNonNull(operationId, "operationId must not be null");
        if (operationId.isBlank()) {
            throw new IllegalArgumentException("operationId must not be blank");
        }
        Objects.requireNonNull(requestDigestHex, "requestDigestHex must not be null");
        if (requestDigestHex.isBlank()) {
            throw new IllegalArgumentException("requestDigestHex must not be blank");
        }
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(logicalKeyId, "logicalKeyId must not be null");
        Objects.requireNonNull(kmsKeyRef, "kmsKeyRef must not be null");
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        Objects.requireNonNull(wrappingSuiteWire, "wrappingSuiteWire must not be null");
        Objects.requireNonNull(hkdfContextVersion, "hkdfContextVersion must not be null");
        Objects.requireNonNull(recipientCertificateFingerprint,
                "recipientCertificateFingerprint must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(envelopeOperationId, "envelopeOperationId must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        if (rootKeyVersion < 0) {
            throw new IllegalArgumentException("rootKeyVersion must not be negative");
        }
        if (businessKeyVersion < 0) {
            throw new IllegalArgumentException("businessKeyVersion must not be negative");
        }
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("expiresAt must be after createdAt");
        }
        envelopeBytes = cloneOrNull(envelopeBytes);
        envelopeDigest = cloneOrNull(envelopeDigest);
        kcv = cloneOrNull(kcv);
        serverEphemeralPublicKey = cloneOrNull(serverEphemeralPublicKey);
        hkdfSalt = cloneOrNull(hkdfSalt);
        nonce = cloneOrNull(nonce);
        ciphertext = cloneOrNull(ciphertext);
        authenticationTag = cloneOrNull(authenticationTag);
        canonicalAad = cloneOrNull(canonicalAad);
        aadDigest = cloneOrNull(aadDigest);
    }

    @Override
    public byte[] envelopeBytes() {
        return cloneOrNull(envelopeBytes);
    }

    @Override
    public byte[] envelopeDigest() {
        return cloneOrNull(envelopeDigest);
    }

    @Override
    public byte[] kcv() {
        return cloneOrNull(kcv);
    }

    @Override
    public byte[] serverEphemeralPublicKey() {
        return cloneOrNull(serverEphemeralPublicKey);
    }

    @Override
    public byte[] hkdfSalt() {
        return cloneOrNull(hkdfSalt);
    }

    @Override
    public byte[] nonce() {
        return cloneOrNull(nonce);
    }

    @Override
    public byte[] ciphertext() {
        return cloneOrNull(ciphertext);
    }

    @Override
    public byte[] authenticationTag() {
        return cloneOrNull(authenticationTag);
    }

    @Override
    public byte[] canonicalAad() {
        return cloneOrNull(canonicalAad);
    }

    @Override
    public byte[] aadDigest() {
        return cloneOrNull(aadDigest);
    }

    private static byte[] cloneOrNull(byte[] value) {
        return value == null ? null : value.clone();
    }

    /**
     * 非敏感描述：不展开信封/AAD/密文内容。
     */
    @Override
    public String toString() {
        return "DerivedWrapResultRecord{operationId='" + operationId + "'"
                + ", requestDigestHex='" + requestDigestHex + "'"
                + ", aadProfileId=" + aadProfileId
                + ", status=" + status
                + ", logicalKeyId='" + logicalKeyId + "'"
                + ", rootKeyVersion=" + rootKeyVersion
                + ", derivationVersion='" + derivationVersion + "'"
                + ", wrappingSuiteWire='" + wrappingSuiteWire + "'"
                + ", purpose=" + purpose
                + ", businessKeyVersion=" + businessKeyVersion
                + ", envelopeBytes=" + (envelopeBytes == null ? "null" : "[" + envelopeBytes.length + " bytes]")
                + ", envelopeDigest=" + (envelopeDigest == null ? "null" : "[" + envelopeDigest.length + " bytes]")
                + ", kcv=" + (kcv == null ? "null" : "[" + kcv.length + " bytes]")
                + ", canonicalAad=" + (canonicalAad == null ? "null" : "[" + canonicalAad.length + " bytes]")
                + ", createdAt=" + createdAt + ", expiresAt=" + expiresAt
                + ", failReason=" + failReason + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DerivedWrapResultRecord that)) {
            return false;
        }
        return rootKeyVersion == that.rootKeyVersion
                && businessKeyVersion == that.businessKeyVersion
                && Objects.equals(operationId, that.operationId)
                && Objects.equals(requestDigestHex, that.requestDigestHex)
                && Objects.equals(aadProfileId, that.aadProfileId)
                && status == that.status
                && Objects.equals(logicalKeyId, that.logicalKeyId)
                && Objects.equals(kmsKeyRef, that.kmsKeyRef)
                && Objects.equals(derivationVersion, that.derivationVersion)
                && Objects.equals(wrappingSuiteWire, that.wrappingSuiteWire)
                && Objects.equals(hkdfContextVersion, that.hkdfContextVersion)
                && Objects.equals(recipientCertificateFingerprint, that.recipientCertificateFingerprint)
                && purpose == that.purpose
                && Objects.equals(envelopeOperationId, that.envelopeOperationId)
                && Objects.equals(createdAt, that.createdAt)
                && Objects.equals(expiresAt, that.expiresAt)
                && Objects.equals(failReason, that.failReason)
                && Arrays.equals(envelopeBytes, that.envelopeBytes)
                && Arrays.equals(envelopeDigest, that.envelopeDigest)
                && Arrays.equals(kcv, that.kcv)
                && Arrays.equals(serverEphemeralPublicKey, that.serverEphemeralPublicKey)
                && Arrays.equals(hkdfSalt, that.hkdfSalt)
                && Arrays.equals(nonce, that.nonce)
                && Arrays.equals(ciphertext, that.ciphertext)
                && Arrays.equals(authenticationTag, that.authenticationTag)
                && Arrays.equals(canonicalAad, that.canonicalAad)
                && Arrays.equals(aadDigest, that.aadDigest);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(operationId, requestDigestHex, aadProfileId, status, logicalKeyId,
                kmsKeyRef, rootKeyVersion, derivationVersion, wrappingSuiteWire, hkdfContextVersion,
                recipientCertificateFingerprint, purpose, businessKeyVersion, envelopeOperationId,
                createdAt, expiresAt, failReason);
        result = 31 * result + Arrays.hashCode(envelopeBytes);
        result = 31 * result + Arrays.hashCode(envelopeDigest);
        result = 31 * result + Arrays.hashCode(kcv);
        result = 31 * result + Arrays.hashCode(serverEphemeralPublicKey);
        result = 31 * result + Arrays.hashCode(hkdfSalt);
        result = 31 * result + Arrays.hashCode(nonce);
        result = 31 * result + Arrays.hashCode(ciphertext);
        result = 31 * result + Arrays.hashCode(authenticationTag);
        result = 31 * result + Arrays.hashCode(canonicalAad);
        result = 31 * result + Arrays.hashCode(aadDigest);
        return result;
    }
}
