package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * ECDH-ES P-256 信封结构化视图 v1（FW-SEC-DSN-CR-015 §4.1）。
 * <p>
 * 对 FW 私有 canonical 信封（{@link DerivedWrappedKeyEnvelopeV1}）的<strong>只读结构化投影</strong>，
 * 供业务消费者（如 VMD 协议 Adapter）直接取得 {@code ciphertext}、P-256 ephemeral 公钥、
 * HKDF salt/context、nonce、tag、canonical AAD、证书摘要与版本元数据，无需解析私有 18-segment bytes。
 * <p>
 * <strong>安全边界</strong>：
 * <ul>
 *   <li>所有 {@code byte[]} 组件构造与访问均防御性复制；</li>
 *   <li>固定长度校验（P-256 uncompressed key=65、salt=32、nonce=12、tag=16、digest=32、KCV=3），
 *       任一非法即构造失败（fail-closed）；</li>
 *   <li>{@code businessKeyVersion} 合法范围为 {@code 1..2^63-1}；</li>
 *   <li>{@link #toString()} 只输出格式/套件/版本与长度摘要，不展开任何 bytes。</li>
 * </ul>
 * 视图<strong>不</strong>参与密码学计算，也不修改 {@code ciphertext}/canonical AAD/digest；
 * canonical envelope 与 digest 的构造仍归 framework core（CR-015 RD-015-4）。
 *
 * @param formatVersion                  信封格式版本（MUST 等于 {@link #FORMAT_VERSION_V1}）
 * @param wrappingSuite                  封装套件（MUST 为 ECDH-ES 套件）
 * @param serverEphemeralPublicKey       服务端临时 EC 公钥（P-256 SEC1 uncompressed，65 字节）
 * @param hkdfSalt                       HKDF salt（32 字节）
 * @param hkdfContextVersion             HKDF info/context 版本（首期 {@code v1}）
 * @param nonce                          AES-GCM nonce（12 字节）
 * @param ciphertext                     AES-GCM 密文（{@code wrapped_key}）
 * @param authenticationTag              AES-GCM tag（16 字节）
 * @param canonicalAad                   canonical AAD 原始字节（{@code EnvelopeAadV1}，≤ 1 KiB）
 * @param aadDigest                      AAD 摘要（SHA-256，32 字节）
 * @param recipientCertificateDigest     收方证书摘要（SHA-256，32 字节）
 * @param logicalKeyId                   逻辑派生实例标识
 * @param purpose                        派生用途
 * @param businessKeyVersion             VMD 业务版本（1..2^63-1）
 * @param rootKeyVersion                 Transit/HSM 根版本
 * @param derivationVersion             派生格式版本
 * @param operationId                    操作标识（对账主键）
 * @param envelopeDigest                 信封摘要（SHA-256，32 字节）
 * @param keyCheckValue                  密钥校验值（3 字节）
 * @param aadProfileId                  使用的 AAD profile 标识（CR-020；null = 无 profile 旧格式/legacy core AAD）
 */
public record EcdhEsP256EnvelopeViewV1(
        int formatVersion,
        WrappingSuite wrappingSuite,
        byte[] serverEphemeralPublicKey,
        byte[] hkdfSalt,
        String hkdfContextVersion,
        byte[] nonce,
        byte[] ciphertext,
        byte[] authenticationTag,
        byte[] canonicalAad,
        byte[] aadDigest,
        byte[] recipientCertificateDigest,
        String logicalKeyId,
        KeyPurpose purpose,
        long businessKeyVersion,
        long rootKeyVersion,
        String derivationVersion,
        String operationId,
        byte[] envelopeDigest,
        byte[] keyCheckValue,
        String aadProfileId) implements DerivedWrappedKeyEnvelopeView, java.io.Serializable {

    /** 受治理信封格式标识（对应 PAR-PROTO {@code KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1}）。 */
    public static final String ENVELOPE_FORMAT = "ECDH_ES_P256_V1";
    /** 首期信封格式版本（对应 PAR-PROTO {@code format_version} MUST 等于 1）。 */
    public static final int FORMAT_VERSION_V1 = 1;
    /** P-256 SEC1 uncompressed 公钥长度（{@code 0x04 || X || Y}）。 */
    public static final int SERVER_EPHEMERAL_PUBLIC_KEY_LENGTH = 65;
    /** HKDF salt 固定长度。 */
    public static final int HKDF_SALT_LENGTH = 32;
    /** AES-GCM nonce 固定长度。 */
    public static final int NONCE_LENGTH = 12;
    /** AES-GCM tag 固定长度。 */
    public static final int AUTHENTICATION_TAG_LENGTH = 16;
    /** SHA-256 摘要固定长度（aadDigest / recipientCertificateDigest / envelopeDigest）。 */
    public static final int DIGEST_LENGTH = 32;
    /** KCV 固定长度（{@code first_3_bytes(SHA-256(businessKey))}）。 */
    public static final int KEY_CHECK_VALUE_LENGTH = 3;
    /** canonical AAD 上限（1 KiB）。 */
    public static final int MAX_CANONICAL_AAD_LENGTH = 1024;
    /** {@code businessKeyVersion} 合法上限（2^63-1）。 */
    public static final long MAX_BUSINESS_KEY_VERSION = Long.MAX_VALUE;

    /** P-256 SEC1 uncompressed 点首字节。 */
    private static final byte UNCOMPRESSED_POINT_PREFIX = 0x04;

    public EcdhEsP256EnvelopeViewV1 {
        Objects.requireNonNull(wrappingSuite, "wrappingSuite must not be null");
        requireNonBlank(hkdfContextVersion, "hkdfContextVersion");
        Objects.requireNonNull(logicalKeyId, "logicalKeyId must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(derivationVersion, "derivationVersion must not be null");
        Objects.requireNonNull(operationId, "operationId must not be null");
        if (formatVersion != FORMAT_VERSION_V1) {
            throw new IllegalArgumentException("unsupported envelope formatVersion: " + formatVersion
                    + "（首期仅支持 " + FORMAT_VERSION_V1 + "）");
        }
        if (!wrappingSuite.isEcdh()) {
            throw new IllegalArgumentException("EcdhEsP256EnvelopeViewV1 requires an ECDH-ES wrapping suite, got "
                    + wrappingSuite);
        }
        if (businessKeyVersion < 1 || businessKeyVersion > MAX_BUSINESS_KEY_VERSION) {
            throw new IllegalArgumentException("businessKeyVersion out of range 1..2^63-1: " + businessKeyVersion);
        }
        if (rootKeyVersion < 0) {
            throw new IllegalArgumentException("rootKeyVersion must not be negative: " + rootKeyVersion);
        }
        serverEphemeralPublicKey = requireFixedLength(serverEphemeralPublicKey,
                SERVER_EPHEMERAL_PUBLIC_KEY_LENGTH, "serverEphemeralPublicKey");
        if (serverEphemeralPublicKey[0] != UNCOMPRESSED_POINT_PREFIX) {
            throw new IllegalArgumentException(
                    "serverEphemeralPublicKey must be a P-256 SEC1 uncompressed point (0x04 prefix)");
        }
        hkdfSalt = requireFixedLength(hkdfSalt, HKDF_SALT_LENGTH, "hkdfSalt");
        nonce = requireFixedLength(nonce, NONCE_LENGTH, "nonce");
        ciphertext = requireNonEmpty(ciphertext, "ciphertext");
        authenticationTag = requireFixedLength(authenticationTag, AUTHENTICATION_TAG_LENGTH, "authenticationTag");
        canonicalAad = requireNonEmpty(canonicalAad, "canonicalAad");
        if (canonicalAad.length > MAX_CANONICAL_AAD_LENGTH) {
            throw new IllegalArgumentException("canonicalAad exceeds max " + MAX_CANONICAL_AAD_LENGTH + " bytes");
        }
        aadDigest = requireFixedLength(aadDigest, DIGEST_LENGTH, "aadDigest");
        recipientCertificateDigest = requireFixedLength(recipientCertificateDigest, DIGEST_LENGTH,
                "recipientCertificateDigest");
        envelopeDigest = requireFixedLength(envelopeDigest, DIGEST_LENGTH, "envelopeDigest");
        keyCheckValue = requireFixedLength(keyCheckValue, KEY_CHECK_VALUE_LENGTH, "keyCheckValue");
        if (aadProfileId != null && aadProfileId.isBlank()) {
            throw new IllegalArgumentException("aadProfileId must not be blank when present");
        }
    }

    /**
     * 兼容构造（CR-020 §6 additive）：不携带 aadProfileId 的旧格式视图（{@code aadProfileId = null}）。
     * <p>
     * 保留旧 19 参构造的 JVM descriptor，使既有消费者（framework/VMD/VAGW/TSP）二进制与源码兼容；
     * 新 V2C 结果必须通过带 aadProfileId 的 canonical 构造构建。
     */
    public EcdhEsP256EnvelopeViewV1(
            int formatVersion,
            WrappingSuite wrappingSuite,
            byte[] serverEphemeralPublicKey,
            byte[] hkdfSalt,
            String hkdfContextVersion,
            byte[] nonce,
            byte[] ciphertext,
            byte[] authenticationTag,
            byte[] canonicalAad,
            byte[] aadDigest,
            byte[] recipientCertificateDigest,
            String logicalKeyId,
            KeyPurpose purpose,
            long businessKeyVersion,
            long rootKeyVersion,
            String derivationVersion,
            String operationId,
            byte[] envelopeDigest,
            byte[] keyCheckValue) {
        this(formatVersion, wrappingSuite, serverEphemeralPublicKey, hkdfSalt, hkdfContextVersion,
                nonce, ciphertext, authenticationTag, canonicalAad, aadDigest, recipientCertificateDigest,
                logicalKeyId, purpose, businessKeyVersion, rootKeyVersion, derivationVersion,
                operationId, envelopeDigest, keyCheckValue, null);
    }

    @Override
    public String envelopeFormat() {
        return ENVELOPE_FORMAT;
    }

    @Override
    public byte[] serverEphemeralPublicKey() {
        return serverEphemeralPublicKey.clone();
    }

    @Override
    public byte[] hkdfSalt() {
        return hkdfSalt.clone();
    }

    @Override
    public byte[] nonce() {
        return nonce.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public byte[] authenticationTag() {
        return authenticationTag.clone();
    }

    @Override
    public byte[] canonicalAad() {
        return canonicalAad.clone();
    }

    @Override
    public byte[] aadDigest() {
        return aadDigest.clone();
    }

    @Override
    public byte[] recipientCertificateDigest() {
        return recipientCertificateDigest.clone();
    }

    @Override
    @Deprecated
    public byte[] envelopeDigest() {
        // CR-020 §6：兼容期保留，委托 core 值；新 V2C Adapter 必须使用 coreEnvelopeDigest()
        return envelopeDigest.clone();
    }

    @Override
    public byte[] coreEnvelopeDigest() {
        return envelopeDigest.clone();
    }

    @Override
    public String aadProfileId() {
        return aadProfileId;
    }

    @Override
    public byte[] keyCheckValue() {
        return keyCheckValue.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof EcdhEsP256EnvelopeViewV1 that)) {
            return false;
        }
        return formatVersion == that.formatVersion
                && businessKeyVersion == that.businessKeyVersion
                && rootKeyVersion == that.rootKeyVersion
                && wrappingSuite == that.wrappingSuite
                && Arrays.equals(serverEphemeralPublicKey, that.serverEphemeralPublicKey)
                && Arrays.equals(hkdfSalt, that.hkdfSalt)
                && Objects.equals(hkdfContextVersion, that.hkdfContextVersion)
                && Arrays.equals(nonce, that.nonce)
                && Arrays.equals(ciphertext, that.ciphertext)
                && Arrays.equals(authenticationTag, that.authenticationTag)
                && Arrays.equals(canonicalAad, that.canonicalAad)
                && Arrays.equals(aadDigest, that.aadDigest)
                && Arrays.equals(recipientCertificateDigest, that.recipientCertificateDigest)
                && Objects.equals(logicalKeyId, that.logicalKeyId)
                && purpose == that.purpose
                && Objects.equals(derivationVersion, that.derivationVersion)
                && Objects.equals(operationId, that.operationId)
                && Arrays.equals(envelopeDigest, that.envelopeDigest)
                && Arrays.equals(keyCheckValue, that.keyCheckValue);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(formatVersion, wrappingSuite, hkdfContextVersion, logicalKeyId,
                purpose, businessKeyVersion, rootKeyVersion, derivationVersion, operationId);
        result = 31 * result + Arrays.hashCode(serverEphemeralPublicKey);
        result = 31 * result + Arrays.hashCode(hkdfSalt);
        result = 31 * result + Arrays.hashCode(nonce);
        result = 31 * result + Arrays.hashCode(ciphertext);
        result = 31 * result + Arrays.hashCode(authenticationTag);
        result = 31 * result + Arrays.hashCode(canonicalAad);
        result = 31 * result + Arrays.hashCode(aadDigest);
        result = 31 * result + Arrays.hashCode(recipientCertificateDigest);
        result = 31 * result + Arrays.hashCode(envelopeDigest);
        result = 31 * result + Arrays.hashCode(keyCheckValue);
        return result;
    }

    /**
     * 非敏感描述：只输出格式/套件/版本与 bytes 长度，不展开任何密文材料（CR-015 §6）。
     */
    @Override
    public String toString() {
        return "EcdhEsP256EnvelopeViewV1{envelopeFormat='" + ENVELOPE_FORMAT
                + "', formatVersion=" + formatVersion
                + ", wrappingSuite=" + wrappingSuite
                + ", hkdfContextVersion='" + hkdfContextVersion + "'"
                + ", logicalKeyId='" + logicalKeyId + "'"
                + ", purpose=" + purpose
                + ", businessKeyVersion=" + businessKeyVersion
                + ", rootKeyVersion=" + rootKeyVersion
                + ", derivationVersion='" + derivationVersion + "'"
                + ", operationId='" + operationId + "'"
                + ", aadProfileId=" + (aadProfileId == null ? "null" : "'" + aadProfileId + "'")
                + ", serverEphemeralPublicKey=" + lengthOf(serverEphemeralPublicKey)
                + ", hkdfSalt=" + lengthOf(hkdfSalt)
                + ", nonce=" + lengthOf(nonce)
                + ", ciphertext=" + lengthOf(ciphertext)
                + ", authenticationTag=" + lengthOf(authenticationTag)
                + ", canonicalAad=" + lengthOf(canonicalAad)
                + ", aadDigest=" + lengthOf(aadDigest)
                + ", recipientCertificateDigest=" + lengthOf(recipientCertificateDigest)
                + ", envelopeDigest=" + lengthOf(envelopeDigest)
                + ", keyCheckValue=" + lengthOf(keyCheckValue) + '}';
    }

    private static String lengthOf(byte[] value) {
        return value == null ? "null" : "[" + value.length + " bytes]";
    }

    private static void requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be null or blank");
        }
    }

    private static byte[] requireFixedLength(byte[] value, int expected, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        if (value.length != expected) {
            throw new IllegalArgumentException(name + " must be exactly " + expected + " bytes, got " + value.length);
        }
        return value.clone();
    }

    private static byte[] requireNonEmpty(byte[] value, String name) {
        if (value == null || value.length == 0) {
            throw new IllegalArgumentException(name + " must not be null or empty");
        }
        return value.clone();
    }
}
