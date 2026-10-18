package net.hwyz.iov.cloud.framework.security.crypto.support;

import net.hwyz.iov.cloud.framework.security.crypto.client.FeignKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyEnvelopeCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;

/**
 * 派生封装信封测试夹具（FW-SEC-DSN-CR-014 §3.2/§3.3/§4）。
 * <p>
 * 以测试范围参考实现（{@link EcdhP256}）对一个业务密钥执行
 * ECDH-ES P-256 + HKDF-SHA-256 + AES-256-GCM 封装，产出与契约一致的
 * {@link DerivedWrappedKeyEnvelopeV1} 与 Provider 响应 DTO，用于 framework 侧
 * 编排、canonical 校验与字节级幂等的端到端验证。
 */
public final class DerivedEnvelopeFixture {

    private static final WrappingSuite SUITE = WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM;

    private DerivedEnvelopeFixture() {
    }

    /**
     * 封装参数（全部为受治理的声明值）。
     */
    public record Params(
            ECPublicKey recipientPublicKey,
            byte[] businessKey,
            byte[] kcv,
            String requestId,
            String businessDomain,
            KeyPurpose purpose,
            String keyId,
            long businessKeyVersion,
            long rootKeyVersion,
            String derivationVersion,
            String recipientCertificateFingerprint,
            String operationId,
            String logicalKeyId,
            String kmsKeyRef) {

        /** 惯用缺省构造：kcv 由 businessKey 推导，logicalKeyId=keyId。 */
        public static Params of(ECPublicKey recipientPublicKey, byte[] businessKey, String requestId,
                                String businessDomain, KeyPurpose purpose, String keyId,
                                long businessKeyVersion, long rootKeyVersion, String derivationVersion,
                                String recipientCertificateFingerprint, String operationId,
                                String kmsKeyRef) throws Exception {
            return new Params(recipientPublicKey, businessKey, EcdhP256.kcvOf(businessKey), requestId,
                    businessDomain, purpose, keyId, businessKeyVersion, rootKeyVersion, derivationVersion,
                    recipientCertificateFingerprint, operationId, keyId, kmsKeyRef);
        }
    }

    /**
     * 封装产物：canonical 信封、可回填的 Provider 响应、业务密钥明文（仅测试断言用）。
     */
    public record Built(DerivedWrappedKeyEnvelopeV1 envelope,
                        FeignKmsClient.DerivedWrapResponse response,
                        byte[] businessKey,
                        String kdfInfo) {
    }

    public static Built seal(Params params) throws Exception {
        return seal(params, true);
    }

    /**
     * 执行封装并组装响应。
     *
     * @param params              封装参数
     * @param providerEchoBytes   是否回填 {@code envelopeBytes}（用于验证 Provider 回传一致路径）
     */
    public static Built seal(Params params, boolean providerEchoBytes) throws Exception {
        byte[] aad = DerivedKeyEnvelopeCanonical.aadBytes(aadOf(params));
        String kdfInfo = DerivedKeyEnvelopeCanonical.kdfInfo(params.requestId(), params.businessDomain(),
                params.purpose(), params.keyId(), params.businessKeyVersion(),
                params.recipientCertificateFingerprint());

        KeyPair ephemeral = EcdhP256.generateKeyPair();
        byte[] salt = EcdhP256.randomBytes(32);
        byte[] nonce = EcdhP256.randomBytes(12);
        byte[] shared = EcdhP256.ecdh(ephemeral.getPrivate(), params.recipientPublicKey());
        byte[] kek = EcdhP256.hkdfSha256(shared, salt, kdfInfo.getBytes(StandardCharsets.UTF_8), 32);
        byte[] ciphertextAndTag = EcdhP256.aesGcmEncrypt(kek, nonce, aad, params.businessKey());
        byte[] ciphertext = EcdhP256.splitCiphertext(ciphertextAndTag);
        byte[] tag = EcdhP256.splitTag(ciphertextAndTag);
        byte[] aadDigest = CanonicalEncoding.sha256(aad);

        DerivedWrappedKeyEnvelopeV1 draft = new DerivedWrappedKeyEnvelopeV1(
                DerivedWrappedKeyEnvelopeV1.V1, SUITE,
                EcdhP256.encodeUncompressed((ECPublicKey) ephemeral.getPublic()),
                salt, DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1, nonce, ciphertext, tag,
                aad, aadDigest, params.recipientCertificateFingerprint(), params.logicalKeyId(),
                params.purpose(), params.businessKeyVersion(), params.rootKeyVersion(),
                params.derivationVersion(), params.kcv(), params.operationId(), null);
        byte[] envelopeDigest = DerivedKeyEnvelopeCanonical.envelopeDigest(draft);

        DerivedWrappedKeyEnvelopeV1 envelope = new DerivedWrappedKeyEnvelopeV1(
                DerivedWrappedKeyEnvelopeV1.V1, SUITE,
                EcdhP256.encodeUncompressed((ECPublicKey) ephemeral.getPublic()),
                salt, DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1, nonce, ciphertext, tag,
                aad, aadDigest, params.recipientCertificateFingerprint(), params.logicalKeyId(),
                params.purpose(), params.businessKeyVersion(), params.rootKeyVersion(),
                params.derivationVersion(), params.kcv(), params.operationId(), envelopeDigest);

        FeignKmsClient.DerivedWrapResponse response = new FeignKmsClient.DerivedWrapResponse();
        response.setLogicalKeyId(params.logicalKeyId());
        response.setKmsKeyRef(params.kmsKeyRef());
        response.setRootKeyVersion((int) params.rootKeyVersion());
        response.setDerivationVersion(params.derivationVersion());
        response.setPurpose(params.purpose().name());
        response.setBusinessKeyVersion(params.businessKeyVersion());
        response.setWrappingSuite(SUITE.wireName());
        response.setEnvelopeVersion(DerivedWrappedKeyEnvelopeV1.V1);
        response.setServerEphemeralPublicKey(envelope.serverEphemeralPublicKey());
        response.setHkdfSalt(salt);
        response.setHkdfContextVersion(DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1);
        response.setNonce(nonce);
        response.setCiphertext(ciphertext);
        response.setAuthenticationTag(tag);
        response.setAad(aad);
        response.setAadDigest(aadDigest);
        response.setRecipientCertificateFingerprint(params.recipientCertificateFingerprint());
        if (providerEchoBytes) {
            response.setEnvelopeBytes(DerivedKeyEnvelopeCanonical.envelopeBytesWithoutDigest(envelope));
        }
        response.setEnvelopeDigest(envelopeDigest);
        response.setKcv(CanonicalEncoding.hexLower(params.kcv()));
        response.setOperationId(params.operationId());

        return new Built(envelope, response, params.businessKey(), kdfInfo);
    }

    public static EnvelopeAadV1 aadOf(Params params) {
        return new EnvelopeAadV1(DerivedWrappedKeyEnvelopeV1.V1, SUITE, params.requestId(),
                params.businessDomain(), params.purpose(), params.keyId(), params.businessKeyVersion(),
                params.rootKeyVersion(), params.derivationVersion(),
                params.recipientCertificateFingerprint());
    }
}
