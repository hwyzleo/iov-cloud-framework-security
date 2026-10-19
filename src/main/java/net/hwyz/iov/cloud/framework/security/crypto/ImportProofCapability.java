package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EcdsaP1363;
import net.hwyz.iov.cloud.framework.security.crypto.codec.ImportProofCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.exception.ImportProofRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofVerificationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.VerifiedImportProof;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Set;

/**
 * 导入证明验签能力声明与自检（FW-SEC-DSN-CR-016 §8）。
 * <p>
 * 新增 capability {@link #IMPORT_PROOF_VERIFY_ECDSA_P256_V1}：公开 {@code ImportProofVerifier}
 * 可调用、canonical({@code proofInputV1}) 固定向量通过、P1363/low-S codec 固定向量通过、
 * P-256 ECDSA-SHA256 Provider 可用。
 * <p>
 * DOWN 时允许 canonical 构造与诊断，但<strong>不得</strong>向 VMD 声明 proof verification READY；
 * 禁止仅凭 ACK 字段、KCV 或 {@code ImportProofCanonical.matches} 激活业务版本。
 */
public final class ImportProofCapability {

    /** 导入证明 ECDSA P-256/P1363 验签能力标识（FW-SEC-DSN-CR-016 §8）。 */
    public static final String IMPORT_PROOF_VERIFY_ECDSA_P256_V1 = "IMPORT_PROOF_VERIFY_ECDSA_P256_V1";

    private static final Set<String> SUPPORTED = Set.of(IMPORT_PROOF_VERIFY_ECDSA_P256_V1);

    // ==== 自检固定向量（canonical proofInputV1） ====

    static final String SELF_CHECK_REQUEST_ID = "req-1";
    static final String SELF_CHECK_BUSINESS_DOMAIN = "V2C_COMM_ROOT";
    static final String SELF_CHECK_KEY_ID = "logical-v2c-uplink";
    static final long SELF_CHECK_BUSINESS_KEY_VERSION = 7L;
    static final String SELF_CHECK_ENVELOPE_DIGEST_HEX =
            "71ebe7d7d6c87699910d0093af8e99df3a149fd500cda64bd90505b4c127c933";
    static final String SELF_CHECK_KCV_HEX = "0a0b0c";
    static final String SELF_CHECK_PROOF_INPUT_HEX =
            "000000166f70656e696f767c6b657970726f762d61636b7c7631000000057265712d31"
                    + "0000000d5632435f434f4d4d5f524f4f54000000010100000020"
                    + "d71ab5437ac14e57c51bb541ab2bad89c3f9a27e6fd8e7d7a7cfef05ad4dacc6"
                    + "000000080000000000000007"
                    + "0000002071ebe7d7d6c87699910d0093af8e99df3a149fd500cda64bd90505b4c127c933"
                    + "000000030a0b0c";

    private ImportProofCapability() {
    }

    /**
     * 本 artifact 声明的能力集合（不可变）。
     */
    public static Set<String> supported() {
        return SUPPORTED;
    }

    /**
     * 是否声明支持指定能力。
     *
     * @param capability 能力标识
     */
    public static boolean supports(String capability) {
        return capability != null && SUPPORTED.contains(capability);
    }

    /**
     * 公开 {@code ImportProofVerifier#verify(ImportProofVerificationRequest)} 是否可调用。
     */
    public static boolean publicApiAvailable() {
        try {
            Method verify = ImportProofVerifier.class.getMethod("verify", ImportProofVerificationRequest.class);
            return Modifier.isPublic(verify.getModifiers())
                    && verify.getReturnType() == VerifiedImportProof.class;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    /**
     * 能力静态自检（不依赖 Spring 上下文）：公开 API + canonical 固定向量 + P1363/low-S + ECDSA Provider。
     *
     * @return READY 返回 true
     */
    public static boolean selfCheckReady() {
        return publicApiAvailable() && canonicalVectorReady() && p1363ProviderReady();
    }

    /**
     * canonical({@code proofInputV1}) 冻结固定向量自检。
     */
    static boolean canonicalVectorReady() {
        try {
            byte[] proofInput = ImportProofCanonical.proofInputV1(
                    SELF_CHECK_REQUEST_ID, SELF_CHECK_BUSINESS_DOMAIN, KeyPurpose.UPLINK_AEAD,
                    SELF_CHECK_KEY_ID, SELF_CHECK_BUSINESS_KEY_VERSION,
                    hex(SELF_CHECK_ENVELOPE_DIGEST_HEX), hex(SELF_CHECK_KCV_HEX));
            return SELF_CHECK_PROOF_INPUT_HEX.equals(CanonicalEncoding.hexLower(proofInput));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * P1363/low-S codec 与 ECDSA-SHA256 Provider 固定向量自检（含正向与负向）。
     */
    static boolean p1363ProviderReady() {
        if (!EcdsaP1363.providerAvailable()) {
            return false;
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = generator.generateKeyPair();

            byte[] message = "import-proof-self-check".getBytes(StandardCharsets.UTF_8);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(message);
            byte[] p1363 = EcdsaP1363.derToP1363(signature.sign());

            if (!EcdsaP1363.verify(keyPair.getPublic(), message, p1363)) {
                return false;
            }
            byte[] tampered = p1363.clone();
            tampered[0] ^= 0x01;
            try {
                return !EcdsaP1363.verify(keyPair.getPublic(), message, tampered);
            } catch (ImportProofRejectedException rejected) {
                // 篡改后落入确定性拒绝也视为负向通过
                return true;
            }
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] hex(String value) {
        return CanonicalEncoding.hexDecode(value);
    }
}
