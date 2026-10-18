package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * 派生封装完整信封 v1（FW-SEC-DSN-CR-014 §4）。
 * <p>
 * 由 Provider 在受控边界内构建的<strong>版本化、自描述</strong>设备专属 Wrapped Key 信封。
 * 持有目标设备私钥的 TBOX SEC/HSM 仅凭本信封即可独立计算 KEK 并完成解封，
 * 不得依赖 VMD/VAGW 注入隐式密码参数。
 * <p>
 * <strong>安全边界</strong>：
 * <ul>
 *   <li>明文业务密钥、KEK、ECDH shared secret 与临时 EC 私钥均<strong>不</strong>在信封中；</li>
 *   <li>只读 / 防御性复制对象，禁止在 {@code toString()}、异常或结构化日志中展开 bytes；</li>
 *   <li>{@code envelopeDigest = SHA-256(canonicalEnvelopeBytesWithoutDigest)}，
 *       由 framework canonical 编码器校验（{@code DerivedKeyEnvelopeCanonical}）。</li>
 * </ul>
 *
 * @param envelopeVersion                信封版本（v1）
 * @param wrappingSuite                  封装套件
 * @param serverEphemeralPublicKey       服务端临时 EC 公钥（P-256 SEC1 uncompressed，65 字节）
 * @param hkdfSalt                       HKDF salt（32 字节）
 * @param hkdfContextVersion             HKDF info/context 版本（v1）
 * @param nonce                          AEAD nonce（12 字节）
 * @param ciphertext                     AEAD 密文
 * @param authenticationTag              AEAD tag（16 字节）
 * @param aad                            canonical AAD 原始字节（EnvelopeAadV1）
 * @param aadDigest                      AAD 摘要（SHA-256）
 * @param recipientCertificateFingerprint 收方证书 SHA-256 指纹（十六进制小写）
 * @param logicalKeyId                   逻辑派生实例标识
 * @param purpose                        派生用途
 * @param businessKeyVersion             VMD 业务版本
 * @param rootKeyVersion                 Transit/HSM 根版本
 * @param derivationVersion             派生格式版本
 * @param kcv                            密钥校验值（first 3 bytes of SHA-256(businessKey)）
 * @param operationId                    操作标识（对账主键）
 * @param envelopeDigest                 信封摘要（SHA-256(canonicalEnvelopeBytesWithoutDigest)）
 */
public record DerivedWrappedKeyEnvelopeV1(
        String envelopeVersion,
        WrappingSuite wrappingSuite,
        byte[] serverEphemeralPublicKey,
        byte[] hkdfSalt,
        String hkdfContextVersion,
        byte[] nonce,
        byte[] ciphertext,
        byte[] authenticationTag,
        byte[] aad,
        byte[] aadDigest,
        String recipientCertificateFingerprint,
        String logicalKeyId,
        KeyPurpose purpose,
        long businessKeyVersion,
        long rootKeyVersion,
        String derivationVersion,
        byte[] kcv,
        String operationId,
        byte[] envelopeDigest) implements java.io.Serializable {

    /** 首期信封版本 */
    public static final String V1 = "v1";
    /** 首期 HKDF context 版本 */
    public static final String HKDF_CONTEXT_V1 = "v1";

    public DerivedWrappedKeyEnvelopeV1 {
        Objects.requireNonNull(envelopeVersion, "envelopeVersion must not be null");
        Objects.requireNonNull(wrappingSuite, "wrappingSuite must not be null");
        Objects.requireNonNull(hkdfContextVersion, "hkdfContextVersion must not be null");
        serverEphemeralPublicKey = cloneOrNull(serverEphemeralPublicKey);
        hkdfSalt = cloneOrNull(hkdfSalt);
        nonce = cloneOrNull(nonce);
        ciphertext = cloneOrNull(ciphertext);
        authenticationTag = cloneOrNull(authenticationTag);
        aad = cloneOrNull(aad);
        aadDigest = cloneOrNull(aadDigest);
        kcv = cloneOrNull(kcv);
        envelopeDigest = cloneOrNull(envelopeDigest);
    }

    private static byte[] cloneOrNull(byte[] value) {
        return value == null ? null : value.clone();
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
    public byte[] aad() {
        return cloneOrNull(aad);
    }

    @Override
    public byte[] aadDigest() {
        return cloneOrNull(aadDigest);
    }

    @Override
    public byte[] kcv() {
        return cloneOrNull(kcv);
    }

    @Override
    public byte[] envelopeDigest() {
        return cloneOrNull(envelopeDigest);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DerivedWrappedKeyEnvelopeV1 that)) {
            return false;
        }
        return businessKeyVersion == that.businessKeyVersion
                && rootKeyVersion == that.rootKeyVersion
                && Objects.equals(envelopeVersion, that.envelopeVersion)
                && wrappingSuite == that.wrappingSuite
                && Arrays.equals(serverEphemeralPublicKey, that.serverEphemeralPublicKey)
                && Arrays.equals(hkdfSalt, that.hkdfSalt)
                && Objects.equals(hkdfContextVersion, that.hkdfContextVersion)
                && Arrays.equals(nonce, that.nonce)
                && Arrays.equals(ciphertext, that.ciphertext)
                && Arrays.equals(authenticationTag, that.authenticationTag)
                && Arrays.equals(aad, that.aad)
                && Arrays.equals(aadDigest, that.aadDigest)
                && Objects.equals(recipientCertificateFingerprint, that.recipientCertificateFingerprint)
                && Objects.equals(logicalKeyId, that.logicalKeyId)
                && purpose == that.purpose
                && Objects.equals(derivationVersion, that.derivationVersion)
                && Arrays.equals(kcv, that.kcv)
                && Objects.equals(operationId, that.operationId)
                && Arrays.equals(envelopeDigest, that.envelopeDigest);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(envelopeVersion, wrappingSuite, hkdfContextVersion,
                recipientCertificateFingerprint, logicalKeyId, purpose, businessKeyVersion,
                rootKeyVersion, derivationVersion, operationId);
        result = 31 * result + Arrays.hashCode(serverEphemeralPublicKey);
        result = 31 * result + Arrays.hashCode(hkdfSalt);
        result = 31 * result + Arrays.hashCode(nonce);
        result = 31 * result + Arrays.hashCode(ciphertext);
        result = 31 * result + Arrays.hashCode(authenticationTag);
        result = 31 * result + Arrays.hashCode(aad);
        result = 31 * result + Arrays.hashCode(aadDigest);
        result = 31 * result + Arrays.hashCode(kcv);
        result = 31 * result + Arrays.hashCode(envelopeDigest);
        return result;
    }

    /**
     * 非敏感描述：不回显信封 bytes 内容，仅输出长度与版本元数据。
     */
    @Override
    public String toString() {
        return "DerivedWrappedKeyEnvelopeV1{envelopeVersion='" + envelopeVersion
                + "', wrappingSuite=" + wrappingSuite
                + ", hkdfContextVersion='" + hkdfContextVersion + "'"
                + ", recipientCertificateFingerprint='" + recipientCertificateFingerprint + "'"
                + ", logicalKeyId='" + logicalKeyId + "'"
                + ", purpose=" + purpose
                + ", businessKeyVersion=" + businessKeyVersion
                + ", rootKeyVersion=" + rootKeyVersion
                + ", derivationVersion='" + derivationVersion + "'"
                + ", operationId='" + operationId + "'"
                + ", serverEphemeralPublicKey=" + lengthOf(serverEphemeralPublicKey)
                + ", hkdfSalt=" + lengthOf(hkdfSalt)
                + ", nonce=" + lengthOf(nonce)
                + ", ciphertext=" + lengthOf(ciphertext)
                + ", authenticationTag=" + lengthOf(authenticationTag)
                + ", aad=" + lengthOf(aad)
                + ", aadDigest=" + lengthOf(aadDigest)
                + ", kcv=" + lengthOf(kcv)
                + ", envelopeDigest=" + lengthOf(envelopeDigest) + '}';
    }

    private static String lengthOf(byte[] value) {
        return value == null ? "null" : "[" + value.length + " bytes]";
    }
}
