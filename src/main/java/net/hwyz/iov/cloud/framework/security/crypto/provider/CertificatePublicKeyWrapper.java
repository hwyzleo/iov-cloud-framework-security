package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyEnvelopeCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.kdf.SessionKdf;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * 本地设备证书公钥封装器（FW-SEC-DSN-CR-019 §5.3/§6）。
 * <p>
 * 在 FW-SEC 受信进程内完成 {@code DERIVED_ROOT} 的证书公钥 Wrap，直接复用
 * CR-014/015 canonical 信封编码（{@link DerivedKeyEnvelopeCanonical} /
 * {@link EnvelopeAadV1} / 结构化 view），保证新旧 Provider 产出字节级一致。
 * <ul>
 *   <li>EC P-256：ECDH-ES + HKDF-SHA256 + AES-256-GCM（随机临时密钥与 nonce 来自批准 SecureRandom）；</li>
 *   <li>RSA：仅 RSA-OAEP-SHA256（禁止 PKCS#1 v1.5、未认证裸 ECDH、固定 nonce）。</li>
 * </ul>
 * ECDH shared secret 与 KEK 为瞬时秘密，封装完成后尽力清零；信封只含非敏感参数与密文。
 */
public class CertificatePublicKeyWrapper {

    private static final String EC_ALGORITHM = "EC";
    private static final String ECDH_ALGORITHM = "ECDH";
    private static final String P256_CURVE = "secp256r1";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BYTES = 16;
    private static final int P256_BYTES = 32;
    private static final int POINT_BYTES = 65;
    private static final int HKDF_SALT_BYTES = 32;
    private static final int GCM_NONCE_BYTES = 12;

    private final SecureRandom secureRandom;

    public CertificatePublicKeyWrapper() {
        this(new SecureRandom());
    }

    public CertificatePublicKeyWrapper(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom must not be null");
    }

    /**
     * 用已验证收方证书公钥封装派生材料并构建 CR-014/015 canonical 信封。
     *
     * @param keyMaterial 派生材料（32 字节，有界内存）
     * @param recipient   已验证收方证据（SPKI/指纹/套件）
     * @param context     信封上下文（逻辑引用/版本/操作）
     * @return canonical 信封（含 envelopeDigest）
     */
    public DerivedWrappedKeyEnvelopeV1 wrap(byte[] keyMaterial, ValidatedRecipientEvidence recipient,
                                            WrapEnvelopeContext context) {
        Objects.requireNonNull(keyMaterial, "keyMaterial must not be null");
        Objects.requireNonNull(recipient, "recipient must not be null");
        Objects.requireNonNull(context, "context must not be null");
        WrappingSuite suite = recipient.validatedWrapSuite();
        if (suite == null) {
            throw TransitException.wrapUnavailable("validatedWrapSuite is null", null);
        }
        switch (suite) {
            case ECDH_ES_P256_HKDF_SHA256_AES256GCM:
                return wrapEcdh(keyMaterial, recipient, context);
            case RSA_OAEP_SHA256:
                return wrapRsa(keyMaterial, recipient, context);
            default:
                throw TransitException.wrapUnavailable(
                        "unsupported wrapping suite: " + suite, null);
        }
    }

    // ==================== ECDH-ES P-256 ====================

    private DerivedWrappedKeyEnvelopeV1 wrapEcdh(byte[] keyMaterial, ValidatedRecipientEvidence recipient,
                                                 WrapEnvelopeContext context) {
        byte[] shared = null;
        byte[] kek = null;
        try {
            ECPublicKey recipientPublic = requireP256(parseEcSpki(recipient.spki()));

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM);
            kpg.initialize(new ECGenParameterSpec(P256_CURVE), secureRandom);
            KeyPair ephemeral = kpg.generateKeyPair();

            KeyAgreement ka = KeyAgreement.getInstance(ECDH_ALGORITHM);
            ka.init(ephemeral.getPrivate());
            ka.doPhase(recipientPublic, true);
            shared = ka.generateSecret();

            byte[] salt = new byte[HKDF_SALT_BYTES];
            secureRandom.nextBytes(salt);
            byte[] info = DerivedKeyEnvelopeCanonical.kdfInfo(
                    context.requestId(), context.businessDomain(), context.purpose(),
                    context.logicalKeyId(), context.businessKeyVersion(),
                    context.recipientCertificateFingerprint())
                    .getBytes(StandardCharsets.UTF_8);
            kek = SessionKdf.deriveSessionKey(shared, salt, info);

            byte[] aad = DerivedKeyEnvelopeCanonical.aadBytes(new EnvelopeAadV1(
                    DerivedWrappedKeyEnvelopeV1.V1,
                    WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                    context.requestId(),
                    context.businessDomain(),
                    context.purpose(),
                    context.logicalKeyId(),
                    context.businessKeyVersion(),
                    context.rootKeyVersion(),
                    context.derivationVersion(),
                    context.recipientCertificateFingerprint()));
            byte[] aadDigest = CanonicalEncoding.sha256(aad);

            byte[] nonce = new byte[GCM_NONCE_BYTES];
            secureRandom.nextBytes(nonce);
            byte[] ciphertextAndTag = aesGcmEncrypt(kek, nonce, aad, keyMaterial);
            byte[] ciphertext = Arrays.copyOf(ciphertextAndTag, ciphertextAndTag.length - GCM_TAG_BYTES);
            byte[] tag = Arrays.copyOfRange(ciphertextAndTag, ciphertextAndTag.length - GCM_TAG_BYTES,
                    ciphertextAndTag.length);

            byte[] ephemeralPub = encodeUncompressed((ECPublicKey) ephemeral.getPublic());
            byte[] kcv = DerivedKeyKcv.first3Sha256(keyMaterial);

            DerivedWrappedKeyEnvelopeV1 envelope = new DerivedWrappedKeyEnvelopeV1(
                    DerivedWrappedKeyEnvelopeV1.V1,
                    WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                    ephemeralPub, salt, DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1,
                    nonce, ciphertext, tag, aad, aadDigest,
                    context.recipientCertificateFingerprint(), context.logicalKeyId(),
                    context.purpose(), context.businessKeyVersion(), context.rootKeyVersion(),
                    context.derivationVersion(), kcv, context.operationId(), null);
            byte[] digest = DerivedKeyEnvelopeCanonical.envelopeDigest(envelope);
            return new DerivedWrappedKeyEnvelopeV1(
                    DerivedWrappedKeyEnvelopeV1.V1,
                    WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                    ephemeralPub, salt, DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1,
                    nonce, ciphertext, tag, aad, aadDigest,
                    context.recipientCertificateFingerprint(), context.logicalKeyId(),
                    context.purpose(), context.businessKeyVersion(), context.rootKeyVersion(),
                    context.derivationVersion(), kcv, context.operationId(), digest);
        } catch (TransitException e) {
            throw e;
        } catch (Exception e) {
            throw TransitException.wrapUnavailable("ECDH-ES P-256 wrap failed: " + e.getMessage(), e);
        } finally {
            zeroize(shared);
            zeroize(kek);
        }
    }

    // ==================== RSA-OAEP-SHA256 ====================

    private DerivedWrappedKeyEnvelopeV1 wrapRsa(byte[] keyMaterial, ValidatedRecipientEvidence recipient,
                                                WrapEnvelopeContext context) {
        try {
            PublicKey publicKey = parseRsaSpki(recipient.spki());
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            // 显式固定 MGF1-SHA-256（避免 JCA 变换默认 MGF1-SHA-1 导致的跨端不一致）
            cipher.init(Cipher.ENCRYPT_MODE, publicKey,
                    new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                            PSource.PSpecified.DEFAULT));
            byte[] ciphertext = cipher.doFinal(keyMaterial);
            byte[] kcv = DerivedKeyKcv.first3Sha256(keyMaterial);

            DerivedWrappedKeyEnvelopeV1 envelope = new DerivedWrappedKeyEnvelopeV1(
                    DerivedWrappedKeyEnvelopeV1.V1,
                    WrappingSuite.RSA_OAEP_SHA256,
                    null, null, DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1,
                    null, ciphertext, null, null, null,
                    context.recipientCertificateFingerprint(), context.logicalKeyId(),
                    context.purpose(), context.businessKeyVersion(), context.rootKeyVersion(),
                    context.derivationVersion(), kcv, context.operationId(), null);
            byte[] digest = DerivedKeyEnvelopeCanonical.envelopeDigest(envelope);
            return new DerivedWrappedKeyEnvelopeV1(
                    DerivedWrappedKeyEnvelopeV1.V1,
                    WrappingSuite.RSA_OAEP_SHA256,
                    null, null, DerivedWrappedKeyEnvelopeV1.HKDF_CONTEXT_V1,
                    null, ciphertext, null, null, null,
                    context.recipientCertificateFingerprint(), context.logicalKeyId(),
                    context.purpose(), context.businessKeyVersion(), context.rootKeyVersion(),
                    context.derivationVersion(), kcv, context.operationId(), digest);
        } catch (TransitException e) {
            throw e;
        } catch (Exception e) {
            throw TransitException.wrapUnavailable("RSA-OAEP-SHA256 wrap failed: " + e.getMessage(), e);
        }
    }

    // ==================== 密码学原语（本地，禁 PKCS#1 v1.5 / 固定 nonce） ====================

    private static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BYTES * 8, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(plaintext);
    }

    private static ECPublicKey parseEcSpki(byte[] spki) {
        if (spki == null || spki.length == 0) {
            throw TransitException.recipientInvalid("recipient SPKI is empty");
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(spki));
            if (!(publicKey instanceof ECPublicKey ecPublicKey)) {
                throw TransitException.recipientInvalid("recipient public key is not EC");
            }
            return ecPublicKey;
        } catch (TransitException e) {
            throw e;
        } catch (Exception e) {
            throw TransitException.recipientInvalid("cannot parse EC SPKI: " + e.getMessage());
        }
    }

    private static PublicKey parseRsaSpki(byte[] spki) {
        if (spki == null || spki.length == 0) {
            throw TransitException.recipientInvalid("recipient SPKI is empty");
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(spki));
            if (!"RSA".equals(publicKey.getAlgorithm())) {
                throw TransitException.recipientInvalid("recipient public key is not RSA");
            }
            return publicKey;
        } catch (TransitException e) {
            throw e;
        } catch (Exception e) {
            throw TransitException.recipientInvalid("cannot parse RSA SPKI: " + e.getMessage());
        }
    }

    /**
     * Provider 最终门禁用：校验已验证套件与 SPKI 算法/曲线匹配（FW-SEC-DSN-CR-019 §5.3）。
     * EC 套件同时校验 P-256 曲线；不匹配返回 false（调用方 fail-closed，Transit 调用恒为 0）。
     */
    public static boolean recipientMatchesSuite(WrappingSuite suite, byte[] spki) {
        if (suite == null || spki == null || spki.length == 0) {
            return false;
        }
        try {
            String keyAlgorithm = net.hwyz.iov.cloud.framework.security.crypto.resolver
                    .CertificateEvidenceValidator.publicKeyAlgorithm(spki);
            WrappingSuite derived = WrappingSuite.forRecipientKeyAlgorithm(keyAlgorithm);
            if (suite != derived) {
                return false;
            }
            if (suite.isEcdh()) {
                requireP256(parseEcSpki(spki));
            }
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * 校验 P-256（secp256r1）曲线与点有效性；其他曲线一律拒绝（fail-closed）。
     */
    private static ECPublicKey requireP256(ECPublicKey publicKey) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC_ALGORITHM);
            parameters.init(new ECGenParameterSpec(P256_CURVE));
            ECParameterSpec p256 = parameters.getParameterSpec(ECParameterSpec.class);
            ECParameterSpec params = publicKey.getParams();
            if (params == null || params.getCurve() == null
                    || !params.getCurve().equals(p256.getCurve())
                    || params.getCurve().getField().getFieldSize() != 256) {
                throw TransitException.recipientInvalid("recipient EC curve is not P-256 (secp256r1)");
            }
            if (ECPoint.POINT_INFINITY.equals(publicKey.getW())) {
                throw TransitException.recipientInvalid("recipient EC point is at infinity");
            }
            return publicKey;
        } catch (TransitException e) {
            throw e;
        } catch (Exception e) {
            throw TransitException.recipientInvalid("cannot validate P-256 curve: " + e.getMessage());
        }
    }

    /**
     * SEC1 uncompressed：{@code 0x04 || X(32) || Y(32)}，共 65 字节。
     */
    private static byte[] encodeUncompressed(ECPublicKey key) {
        byte[] out = new byte[POINT_BYTES];
        out[0] = 0x04;
        System.arraycopy(fixed(key.getW().getAffineX(), P256_BYTES), 0, out, 1, P256_BYTES);
        System.arraycopy(fixed(key.getW().getAffineY(), P256_BYTES), 0, out, 1 + P256_BYTES, P256_BYTES);
        return out;
    }

    private static byte[] fixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        if (raw.length > length) {
            System.arraycopy(raw, raw.length - length, out, 0, length);
        } else {
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        }
        return out;
    }

    private static void zeroize(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
