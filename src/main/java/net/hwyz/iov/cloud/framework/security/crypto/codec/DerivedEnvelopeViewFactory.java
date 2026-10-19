package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeView;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;

import java.util.Objects;

/**
 * 信封结构化视图工厂（FW-SEC-DSN-CR-015 §4.1）。
 * <p>
 * 由 framework core 的 canonical 信封直接构建结构化、只读的
 * {@link DerivedWrappedKeyEnvelopeView}，是业务消费者取得 ciphertext / ECDH 参数 /
 * digest / KCV 的<strong>唯一受治理入口</strong>；消费者禁止解析 {@code envelopeBytes}。
 * <p>
 * 视图构建<strong>只做投影</strong>，不参与任何密码学计算，也不修改 ciphertext、
 * canonical AAD 或 digest（CR-015 RD-015-3/RD-015-4）。首期仅支持 ECDH-ES P-256 v1；
 * 其他套件 fail-closed。
 */
public final class DerivedEnvelopeViewFactory {

    private DerivedEnvelopeViewFactory() {
    }

    /**
     * 将 canonical ECDH-ES v1 信封投影为结构化视图。
     *
     * @param envelope canonical 信封（非空，且套件必须为 ECDH-ES）
     * @return 结构化视图
     * @throws NullPointerException     信封为 null
     * @throws IllegalArgumentException 套件非 ECDH-ES，或证书指纹缺失/非法，或字段长度不合法
     */
    public static EcdhEsP256EnvelopeViewV1 toEcdhEsP256View(DerivedWrappedKeyEnvelopeV1 envelope) {
        Objects.requireNonNull(envelope, "envelope must not be null");
        if (envelope.wrappingSuite() == null || !envelope.wrappingSuite().isEcdh()) {
            throw new IllegalArgumentException(
                    "structured envelope view v1 首期仅支持 ECDH-ES 套件, got " + envelope.wrappingSuite());
        }
        return new EcdhEsP256EnvelopeViewV1(
                EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1,
                envelope.wrappingSuite(),
                envelope.serverEphemeralPublicKey(),
                envelope.hkdfSalt(),
                envelope.hkdfContextVersion(),
                envelope.nonce(),
                envelope.ciphertext(),
                envelope.authenticationTag(),
                envelope.aad(),
                envelope.aadDigest(),
                recipientCertificateDigest(envelope),
                envelope.logicalKeyId(),
                envelope.purpose(),
                envelope.businessKeyVersion(),
                envelope.rootKeyVersion(),
                envelope.derivationVersion(),
                envelope.operationId(),
                envelope.envelopeDigest(),
                envelope.kcv());
    }

    /**
     * 将信封携带的收方证书指纹（小写十六进制）还原为 32 字节 SHA-256 证书摘要。
     *
     * @param envelope canonical 信封
     * @return 32 字节摘要
     * @throws IllegalArgumentException 指纹缺失或长度非 32 字节
     */
    public static byte[] recipientCertificateDigest(DerivedWrappedKeyEnvelopeV1 envelope) {
        String fingerprint = envelope.recipientCertificateFingerprint();
        if (fingerprint == null || fingerprint.isBlank()) {
            throw new IllegalArgumentException("recipientCertificateFingerprint must not be null or blank");
        }
        byte[] digest = CanonicalEncoding.hexDecode(fingerprint);
        if (digest == null || digest.length != EcdhEsP256EnvelopeViewV1.DIGEST_LENGTH) {
            throw new IllegalArgumentException(
                    "recipientCertificateFingerprint must encode a " + EcdhEsP256EnvelopeViewV1.DIGEST_LENGTH
                            + "-byte SHA-256 digest, got "
                            + (digest == null ? "null" : digest.length + " bytes"));
        }
        return digest;
    }
}
