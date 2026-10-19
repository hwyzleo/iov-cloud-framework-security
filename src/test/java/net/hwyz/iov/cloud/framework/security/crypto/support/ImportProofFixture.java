package net.hwyz.iov.cloud.framework.security.crypto.support;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EcdsaP1363;
import net.hwyz.iov.cloud.framework.security.crypto.codec.ImportProofCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * 导入证明验签测试夹具（FW-SEC-DSN-CR-016）。
 * <p>
 * 生成 P-256 + {@code digitalSignature} 的自签名设备证书，并按冻结 canonical {@code proofInputV1}
 * 产生 low-S P1363 证明，供单元/集成测试端到端使用；不引入任何生产依赖。
 */
public final class ImportProofFixture {

    public static final String BUSINESS_DOMAIN = "V2C_COMM_ROOT";

    private ImportProofFixture() {
    }

    public record Material(KeyPair keyPair, X509Certificate certificate, byte[] certificateDer) {

        public byte[] certificateDigest() {
            return CanonicalEncoding.sha256(certificateDer);
        }
    }

    /**
     * 生成 keyUsage=digitalSignature 的自签名 P-256 设备证书（有效期相对当前时刻）。
     */
    public static Material deviceCertificate() throws Exception {
        return deviceCertificate(Instant.now());
    }

    /**
     * 生成 keyUsage=digitalSignature 的自签名 P-256 设备证书，有效期相对给定参考时刻
     * （{@code referenceTime - 1h} ~ {@code referenceTime + 24h}）。
     * <p>
     * 验签测试使用固定 {@link java.time.Clock} 时，必须传入同一参考时刻，避免夹具证书
     * 相对受信任时钟尚未生效而误判为证书策略拒绝。
     */
    public static Material deviceCertificate(Instant referenceTime) throws Exception {
        KeyPair keyPair = TestPkiMaterial.generateKeyPair();
        X509Certificate certificate = TestPkiMaterial.issueEndEntitySelfSigned(
                new X500Name("CN=TBOX-00000000000000000000000000000001"), keyPair,
                BigInteger.valueOf(2026L), KeyUsage.digitalSignature,
                referenceTime.minusSeconds(3600), referenceTime.plusSeconds(24 * 3600));
        return new Material(keyPair, certificate, certificate.getEncoded());
    }

    public static byte[] proofInput(String requestId, KeyPurpose purpose, String keyId,
                                    long businessKeyVersion, byte[] envelopeDigest, byte[] kcv) {
        return ImportProofCanonical.proofInputV1(requestId, BUSINESS_DOMAIN, purpose, keyId,
                businessKeyVersion, envelopeDigest, kcv);
    }

    /**
     * 对 canonical {@code proofInput} 产生 ECDSA P-256/SHA-256 low-S P1363（64 字节）证明。
     */
    public static byte[] signLowS(KeyPair keyPair, byte[] proofInput) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(proofInput);
        return EcdsaP1363.derToP1363(signature.sign());
    }
}
