package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

/**
 * 派生封装信封 canonical 编码器（FW-SEC-DSN-CR-014 §3.2/§3.3/§4）。
 * <p>
 * 跨端（Java/Provider/C++/HSM）<strong>单一权威</strong>的 canonical 字节定义：
 * <ul>
 *   <li>{@link #kdfInfo}：HKDF-SHA-256 的 {@code info} 上下文；</li>
 *   <li>{@link #aadBytes}/{@link #aadDigest}：AES-256-GCM AAD 及其摘要；</li>
 *   <li>{@link #envelopeBytesWithoutDigest}/{@link #envelopeDigest}：信封 canonical bytes 与摘要。</li>
 * </ul>
 * 所有编码均为确定性字段顺序 + UTF-8 + 长度前缀（{@link CanonicalEncoding}），
 * 禁止本地默认字符集/平台换行/未定义 JSON 序列化。
 */
public final class DerivedKeyEnvelopeCanonical {

    /** HKDF info 协议标签（首期） */
    public static final String KDF_INFO_LABEL = "openiov|keyprov-wrap|v1";
    /** 信封版本（首期） */
    public static final String ENVELOPE_VERSION_V1 = DerivedWrappedKeyEnvelopeV1.V1;

    private DerivedKeyEnvelopeCanonical() {
    }

    /**
     * 构造 HKDF-SHA-256 的 canonical {@code info} 上下文（§3.2）：
     * <pre>
     * openiov|keyprov-wrap|v1|{requestId}|{businessDomain}|{purpose}
     *   |{keyId}|{businessKeyVersion}|{recipientCertificateFingerprintHexLower}
     * </pre>
     * 各字段值须先按各自规范化规则处理；指纹统一小写十六进制。
     *
     * @param requestId             请求标识
     * @param businessDomain        业务域
     * @param purpose               派生用途
     * @param keyId                 逻辑密钥标识
     * @param businessKeyVersion    VMD 业务版本
     * @param recipientFingerprint  收方证书指纹（十六进制，大小写不敏感；编码时统一小写）
     * @return info 字符串
     */
    public static String kdfInfo(String requestId, String businessDomain, KeyPurpose purpose,
                                 String keyId, long businessKeyVersion, String recipientFingerprint) {
        return KDF_INFO_LABEL
                + "|" + nullSafe(requestId)
                + "|" + nullSafe(businessDomain)
                + "|" + (purpose == null ? "" : purpose.name())
                + "|" + nullSafe(keyId)
                + "|" + businessKeyVersion
                + "|" + lowerHexOrEmpty(recipientFingerprint);
    }

    /**
     * canonical AAD 字节（长度前缀，固定字段顺序）。
     *
     * @param aad AAD 逻辑字段集
     * @return AAD 字节
     */
    public static byte[] aadBytes(EnvelopeAadV1 aad) {
        return CanonicalEncoding.lengthPrefixedUtf8(
                aad.envelopeVersion(),
                aad.wrappingSuite().name(),
                aad.requestId(),
                aad.businessDomain(),
                aad.purpose() == null ? null : aad.purpose().name(),
                aad.keyId(),
                Long.toString(aad.businessKeyVersion()),
                Long.toString(aad.rootKeyVersion()),
                aad.derivationVersion(),
                lowerHexOrEmpty(aad.recipientCertificateFingerprint()));
    }

    /**
     * AAD 摘要（{@code SHA-256(aadBytes)}）。
     *
     * @param aad AAD 逻辑字段集
     * @return 32 字节摘要
     */
    public static byte[] aadDigest(EnvelopeAadV1 aad) {
        return CanonicalEncoding.sha256(aadBytes(aad));
    }

    /**
     * 信封 canonical bytes（不含 {@code envelopeDigest}），固定字段顺序：
     * envelopeVersion, wrappingSuite, serverEphemeralPublicKey, hkdfSalt, hkdfContextVersion,
     * nonce, ciphertext, authenticationTag, aad, aadDigest, recipientCertificateFingerprint,
     * logicalKeyId, purpose, businessKeyVersion, rootKeyVersion, derivationVersion, kcv, operationId。
     *
     * @param envelope 信封
     * @return canonical bytes
     */
    public static byte[] envelopeBytesWithoutDigest(DerivedWrappedKeyEnvelopeV1 envelope) {
        return CanonicalEncoding.lengthPrefixed(
                utf8(envelope.envelopeVersion()),
                utf8(envelope.wrappingSuite().name()),
                envelope.serverEphemeralPublicKey(),
                envelope.hkdfSalt(),
                utf8(envelope.hkdfContextVersion()),
                envelope.nonce(),
                envelope.ciphertext(),
                envelope.authenticationTag(),
                envelope.aad(),
                envelope.aadDigest(),
                utf8(lowerHexOrEmpty(envelope.recipientCertificateFingerprint())),
                utf8(envelope.logicalKeyId()),
                utf8(envelope.purpose() == null ? null : envelope.purpose().name()),
                utf8(Long.toString(envelope.businessKeyVersion())),
                utf8(Long.toString(envelope.rootKeyVersion())),
                utf8(envelope.derivationVersion()),
                envelope.kcv(),
                utf8(envelope.operationId()));
    }

    /**
     * 计算信封摘要（{@code SHA-256(canonicalEnvelopeBytesWithoutDigest)}）。
     *
     * @param envelope 信封
     * @return 32 字节摘要
     */
    public static byte[] envelopeDigest(DerivedWrappedKeyEnvelopeV1 envelope) {
        return CanonicalEncoding.sha256(envelopeBytesWithoutDigest(envelope));
    }

    /**
     * 校验信封自带的 {@code envelopeDigest} 与重算摘要一致（恒定时间比较）。
     *
     * @param envelope 信封
     * @return 一致返回 true；未携带摘要返回 false
     */
    public static boolean verifyEnvelopeDigest(DerivedWrappedKeyEnvelopeV1 envelope) {
        byte[] declared = envelope.envelopeDigest();
        if (declared == null || declared.length == 0) {
            return false;
        }
        return CanonicalEncoding.constantTimeEquals(declared, envelopeDigest(envelope));
    }

    /**
     * 校验信封自带的 {@code aadDigest} 与 {@code SHA-256(aad)} 一致（恒定时间比较）。
     *
     * @param envelope 信封
     * @return 一致返回 true；未携带返回 false
     */
    public static boolean verifyAadDigest(DerivedWrappedKeyEnvelopeV1 envelope) {
        byte[] declared = envelope.aadDigest();
        if (declared == null || declared.length == 0 || envelope.aad() == null) {
            return false;
        }
        return CanonicalEncoding.constantTimeEquals(declared, CanonicalEncoding.sha256(envelope.aad()));
    }

    private static byte[] utf8(String value) {
        return value == null ? null : value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }

    private static String lowerHexOrEmpty(String value) {
        return value == null ? "" : value.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
