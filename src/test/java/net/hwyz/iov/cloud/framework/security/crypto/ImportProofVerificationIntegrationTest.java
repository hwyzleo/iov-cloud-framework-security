package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EcdsaP1363;
import net.hwyz.iov.cloud.framework.security.crypto.codec.ImportProofCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoAutoConfiguration;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.ImportProofRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofAlgorithm;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofRejectReason;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofVerificationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.VerifiedImportProof;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import net.hwyz.iov.cloud.framework.security.crypto.support.ImportProofFixture;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.Mockito;
import org.springframework.boot.actuate.health.Status;
import org.springframework.core.env.Environment;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 导入证明验签端到端集成测试（FW-SEC-DSN-CR-016 §3/§4/§6/§8/§9）。
 * <p>
 * 以 {@link CryptoAutoConfiguration} 装配真实 {@link CertResolver}（inline DER 来源）、
 * {@link CertificateEvidenceValidator} 与 {@link DefaultImportProofVerifier}，贯通
 * canonical 构建 → 证书证据解析/校验 → 常量时间摘要绑定 → P1363/low-S → ECDSA 验签全链路，
 * 并覆盖 CR-016 §9 测试矩阵的错误分类与 capability/Health 门禁。
 */
class ImportProofVerificationIntegrationTest {

    private static final String REQUEST_ID = "batch-req-0001";
    private static final String KEY_ID = "logical-v2c-uplink";
    private static final long VERSION = 7L;
    private static final byte[] KCV = {0x0a, 0x0b, 0x0c};

    private final CryptoAutoConfiguration configuration = new CryptoAutoConfiguration();
    private final CryptoProperties properties = new CryptoProperties();
    private final CryptoMetrics cryptoMetrics = mock(CryptoMetrics.class);
    private final Clock clock = Clock.systemUTC();

    private Environment environment;
    private ImportProofFixture.Material material;
    private ImportProofVerifier verifier;
    private ImportProofReadiness readiness;
    private byte[] envelopeDigest;

    @BeforeEach
    void setUp() throws Exception {
        material = ImportProofFixture.deviceCertificate();
        envelopeDigest = CanonicalEncoding.sha256("envelope".getBytes(StandardCharsets.UTF_8));

        properties.getPki().getCertificateResolution().setEnabled(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem(
                TestPkiMaterial.pem("CERTIFICATE", material.certificateDer()));
        properties.getPki().getCertificateResolution().getBusinessKeyWrap().setRequireGoodStatus(false);
        properties.getImportProof().setEnabled(true);
        properties.getImportProof().setRequireReadyAtStartup(true);
        properties.getImportProof().getCertificate().setRequireGoodStatus(false);

        environment = mock(Environment.class);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(false);

        CertResolver certResolver = configuration.certResolver(properties, cryptoMetrics,
                new TestObjectProvider<>(), new TestObjectProvider<>(), new TestObjectProvider<>(),
                new TestObjectProvider<>(), environment);
        CertificateEvidenceValidator evidenceValidator = configuration.certificateEvidenceValidator(
                new TestObjectProvider<>(), properties, new TestObjectProvider<>(clock));
        readiness = configuration.importProofReadiness(certResolver, properties, environment);
        verifier = configuration.importProofVerifier(certResolver,
                new TestObjectProvider<>(evidenceValidator), properties, cryptoMetrics, readiness,
                new TestObjectProvider<>(clock), new TestObjectProvider<>());
    }

    private byte[] validProof() throws Exception {
        byte[] proofInput = ImportProofFixture.proofInput(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID,
                VERSION, envelopeDigest, KCV);
        return ImportProofFixture.signLowS(material.keyPair(), proofInput);
    }

    private ImportProofVerificationRequest request(byte[] proof, byte[] expectedDigest,
                                                   ImportProofFixture.Material cert,
                                                   KeyPurpose purpose) {
        return new ImportProofVerificationRequest(ImportProofAlgorithm.ECDSA_P256_SHA256_P1363, proof,
                DeviceCertificateRef.ofCertificate(cert.certificateDer()), expectedDigest,
                REQUEST_ID, ImportProofFixture.BUSINESS_DOMAIN, purpose, KEY_ID, VERSION,
                envelopeDigest, KCV);
    }

    private ImportProofVerificationRequest validRequest() throws Exception {
        return request(validProof(), material.certificateDigest(), material, KeyPurpose.UPLINK_AEAD);
    }

    private static ImportProofRejectReason rejection(Executable action) {
        ImportProofRejectedException ex = assertThrows(ImportProofRejectedException.class, action);
        return ex.rejectReason();
    }

    private static ImportProofFixture.Material materialOf(X509Certificate certificate,
                                                          java.security.KeyPair keyPair)
            throws Exception {
        return new ImportProofFixture.Material(keyPair, certificate, certificate.getEncoded());
    }

    @Test
    void endToEnd_validProof_verifiesAndReportsCapabilityReady() throws Exception {
        VerifiedImportProof result = verifier.verify(validRequest());

        assertArrayEquals(material.certificateDigest(), result.certificateDigest());
        assertEquals(KeyPurpose.UPLINK_AEAD, result.purpose());
        assertNotNull(result.verifiedAt());

        assertTrue(ImportProofCapability.selfCheckReady());
        assertTrue(ImportProofCapability.supports(
                ImportProofCapability.IMPORT_PROOF_VERIFY_ECDSA_P256_V1));
        assertTrue(readiness.isReady());
    }

    @Test
    void endToEnd_healthIndicatorReportsUpWhenReady() {
        ImportProofVerificationHealthIndicator indicator =
                new ImportProofVerificationHealthIndicator(properties, readiness);
        assertEquals(Status.UP, indicator.health().getStatus());
        assertEquals(ImportProofCapability.IMPORT_PROOF_VERIFY_ECDSA_P256_V1,
                indicator.health().getDetails().get("capabilityId"));
    }

    @Test
    void malformedSignatures_rejectedNotRetryable() throws Exception {
        // 63B 长度
        assertEquals(ImportProofRejectReason.INVALID_LENGTH, rejection(() -> verifier.verify(
                request(new byte[63], material.certificateDigest(), material, KeyPurpose.UPLINK_AEAD))));

        // r=0
        byte[] zeroR = validProof();
        Arrays.fill(zeroR, 0, 32, (byte) 0);
        byte[] finalZeroR = zeroR;
        assertEquals(ImportProofRejectReason.INVALID_SCALAR, rejection(() -> verifier.verify(
                request(finalZeroR, material.certificateDigest(), material, KeyPurpose.UPLINK_AEAD))));

        // high-S（s → n - s）
        byte[] highS = validProof();
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(highS, 32, 64));
        System.arraycopy(leftPad32(EcdsaP1363.P256_ORDER_N.subtract(s).toByteArray()), 0, highS, 32, 32);
        byte[] finalHighS = highS;
        assertEquals(ImportProofRejectReason.HIGH_S, rejection(() -> verifier.verify(
                request(finalHighS, material.certificateDigest(), material, KeyPurpose.UPLINK_AEAD))));
    }

    @Test
    void modifiedCanonicalField_signatureInvalid() throws Exception {
        // proof 基于原字段；请求声明不同 requestId → 重建 canonical 后验签失败
        byte[] proof = validProof();
        ImportProofVerificationRequest tampered = new ImportProofVerificationRequest(
                ImportProofAlgorithm.ECDSA_P256_SHA256_P1363, proof,
                DeviceCertificateRef.ofCertificate(material.certificateDer()),
                material.certificateDigest(), "batch-req-0002", ImportProofFixture.BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION, envelopeDigest, KCV);

        assertEquals(ImportProofRejectReason.SIGNATURE_INVALID,
                rejection(() -> verifier.verify(tampered)));
    }

    @Test
    void rootDerivationDomain_contextInvalid() throws Exception {
        // FW-SEC-DSN-CR-016 §3/§4.1：V2C_COMM_ROOT 为根派生标识、非业务域，必须拒绝
        for (String domain : new String[]{"V2C_COMM_ROOT", "v2c_comm", "V2C_COMM_ALIAS"}) {
            ImportProofVerificationRequest request = new ImportProofVerificationRequest(
                    ImportProofAlgorithm.ECDSA_P256_SHA256_P1363, validProof(),
                    DeviceCertificateRef.ofCertificate(material.certificateDer()),
                    material.certificateDigest(), REQUEST_ID, domain,
                    KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION, envelopeDigest, KCV);
            assertEquals(ImportProofRejectReason.CONTEXT_INVALID,
                    rejection(() -> verifier.verify(request)), "businessDomain=" + domain);
        }
    }

    @Test
    void otherDeviceCertificate_rejected() throws Exception {
        // 关闭信任链要求，聚焦验证“其他设备证书”的摘要绑定/签名归属拒绝
        // （信任链不可信另由证书策略路径覆盖）。
        properties.getImportProof().getCertificate().setRequireTrustedChain(false);
        ImportProofFixture.Material other = ImportProofFixture.deviceCertificate();
        // 同 proof、但引用另一设备证书 → 证书策略摘要不匹配
        assertEquals(ImportProofRejectReason.CERTIFICATE_DIGEST_MISMATCH, rejection(() -> verifier.verify(
                request(validProof(), material.certificateDigest(), other, KeyPurpose.UPLINK_AEAD))));
        // 以另一设备证书 + 正确摘要，但用原设备私钥签名 → 无法在换钥后验签成功
        byte[] proofInput = ImportProofFixture.proofInput(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID,
                VERSION, envelopeDigest, KCV);
        byte[] wrongKeyProof = ImportProofFixture.signLowS(material.keyPair(), proofInput);
        assertEquals(ImportProofRejectReason.SIGNATURE_INVALID, rejection(() -> verifier.verify(
                request(wrongKeyProof, other.certificateDigest(), other, KeyPurpose.UPLINK_AEAD))));
    }

    @Test
    void nonP256Certificate_policyRejectedNotRetryable() throws Exception {
        java.security.KeyPair p384 = TestPkiMaterial.generateKeyPair("secp384r1");
        X509Certificate leaf = TestPkiMaterial.issueEndEntitySelfSigned(new X500Name("CN=p384"),
                p384, BigInteger.valueOf(301L), KeyUsage.digitalSignature,
                Instant.now().minusSeconds(3600), Instant.now().plusSeconds(3600));
        ImportProofFixture.Material p384Material = materialOf(leaf, p384);

        CertificateEvidenceRejectedException ex = assertThrows(CertificateEvidenceRejectedException.class,
                () -> verifier.verify(request(validProof(), p384Material.certificateDigest(),
                        p384Material, KeyPurpose.UPLINK_AEAD)));
        assertEquals(CertificateEvidenceRejectedException.Reason.CURVE_NOT_ALLOWED, ex.rejectReason());
        assertFalse(ex.isRetryable());
    }

    @Test
    void expiredCertificate_policyRejectedNotRetryable() throws Exception {
        java.security.KeyPair keyPair = TestPkiMaterial.generateKeyPair();
        X509Certificate leaf = TestPkiMaterial.issueEndEntitySelfSigned(new X500Name("CN=expired"),
                keyPair, BigInteger.valueOf(302L), KeyUsage.digitalSignature,
                Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600));
        ImportProofFixture.Material expired = materialOf(leaf, keyPair);

        CertificateEvidenceRejectedException ex = assertThrows(CertificateEvidenceRejectedException.class,
                () -> verifier.verify(request(validProof(), expired.certificateDigest(), expired,
                        KeyPurpose.UPLINK_AEAD)));
        assertEquals(CertificateEvidenceRejectedException.Reason.CERTIFICATE_EXPIRED, ex.rejectReason());
        assertFalse(ex.isRetryable());
    }

    @Test
    void statusDependencyUnavailable_retryable() throws Exception {
        // 要求 GOOD 状态 + 吊销查询依赖不可达 → 可重试依赖失败（非签名无效）
        properties.getImportProof().getCertificate().setRequireGoodStatus(true);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(true);
        PkiClient pkiClient = mock(PkiClient.class);
        when(pkiClient.checkCertificateStatus(any())).thenThrow(new IllegalStateException("OCSP unreachable"));

        CertResolver certResolver = configuration.certResolver(properties, cryptoMetrics,
                new TestObjectProvider<>(), new TestObjectProvider<>(), new TestObjectProvider<>(pkiClient),
                new TestObjectProvider<>(), environment);
        CertificateEvidenceValidator evidenceValidator = configuration.certificateEvidenceValidator(
                new TestObjectProvider<>(pkiClient), properties, new TestObjectProvider<>(clock));
        ImportProofVerifier statusVerifier = configuration.importProofVerifier(certResolver,
                new TestObjectProvider<>(evidenceValidator), properties, cryptoMetrics,
                configuration.importProofReadiness(certResolver, properties, environment),
                new TestObjectProvider<>(clock), new TestObjectProvider<>());

        ImportProofVerificationRequest request = validRequest();
        CertificateMaterialUnavailableException ex = assertThrows(CertificateMaterialUnavailableException.class,
                () -> statusVerifier.verify(request));
        assertTrue(ex.isRetryable(), "OCSP/CRL 暂不可达属可重试依赖失败（CR-016 §9）");
    }

    @Test
    void revokedCertificate_policyRejectedNotRetryable() throws Exception {
        // 已吊销是证书固有属性：确定性策略拒绝，不得包装为可重试材料/依赖失败（CR-016 §9）
        properties.getImportProof().getCertificate().setRequireGoodStatus(true);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(true);
        PkiClient pkiClient = mock(PkiClient.class);
        when(pkiClient.checkCertificateStatus(any())).thenReturn(new PkiClient.CertificateStatusResult(
                PkiClient.RevocationState.REVOKED, "TBOX-test",
                material.certificate().getNotBefore().toInstant(),
                material.certificate().getNotAfter().toInstant(),
                Instant.now(), null, PkiClient.RevocationSource.OCSP, Instant.now()));

        CertResolver certResolver = configuration.certResolver(properties, cryptoMetrics,
                new TestObjectProvider<>(), new TestObjectProvider<>(), new TestObjectProvider<>(pkiClient),
                new TestObjectProvider<>(), environment);
        CertificateEvidenceValidator evidenceValidator = configuration.certificateEvidenceValidator(
                new TestObjectProvider<>(pkiClient), properties, new TestObjectProvider<>(clock));
        ImportProofVerifier revokedVerifier = configuration.importProofVerifier(certResolver,
                new TestObjectProvider<>(evidenceValidator), properties, cryptoMetrics,
                configuration.importProofReadiness(certResolver, properties, environment),
                new TestObjectProvider<>(clock), new TestObjectProvider<>());

        CertificateEvidenceRejectedException ex = assertThrows(CertificateEvidenceRejectedException.class,
                () -> revokedVerifier.verify(validRequest()));
        assertEquals(CertificateEvidenceRejectedException.Reason.CERTIFICATE_REVOKED, ex.rejectReason());
        assertFalse(ex.isRetryable());
    }

    @Test
    void matchesIsNotSubstituteForCryptoVerification() throws Exception {
        byte[] proofInput = ImportProofFixture.proofInput(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID,
                VERSION, envelopeDigest, KCV);
        // RD-016-4：canonical bytes 相等不代表 proof 验证成功
        assertTrue(ImportProofCanonical.matches(proofInput, proofInput));
        byte[] corrupted = validProof();
        corrupted[0] ^= 0x01;
        byte[] finalCorrupted = corrupted;
        assertEquals(ImportProofRejectReason.SIGNATURE_INVALID, rejection(() -> verifier.verify(
                request(finalCorrupted, material.certificateDigest(), material, KeyPurpose.UPLINK_AEAD))));
    }

    @Test
    void repeatedVerification_isDeterministicAndSideEffectFree() throws Exception {
        ImportProofVerificationRequest request = validRequest();
        VerifiedImportProof first = verifier.verify(request);
        VerifiedImportProof second = verifier.verify(request);
        assertArrayEquals(first.proofInputDigest(), second.proofInputDigest());
        assertArrayEquals(first.certificateDigest(), second.certificateDigest());
        Mockito.verify(cryptoMetrics, Mockito.atLeastOnce()).recordImportProofVerify(Mockito.anyLong());
    }

    @Test
    void rejectedVerification_doesNotLeakSensitiveMaterial() throws Exception {
        byte[] proof = validProof();
        byte[] corrupted = proof.clone();
        corrupted[0] ^= 0x01;
        ImportProofVerificationRequest request =
                request(corrupted, material.certificateDigest(), material, KeyPurpose.UPLINK_AEAD);

        ImportProofRejectedException ex = assertThrows(ImportProofRejectedException.class,
                () -> verifier.verify(request));
        String text = ex.getMessage() + ex;
        assertFalse(text.contains(CanonicalEncoding.hexLower(proof)));
        assertFalse(text.contains(CanonicalEncoding.hexLower(material.certificateDer())));
        assertFalse(text.contains(KEY_ID));
    }

    private static byte[] leftPad32(byte[] value) {
        byte[] out = new byte[32];
        if (value.length >= 32) {
            System.arraycopy(value, value.length - 32, out, 0, 32);
        } else {
            System.arraycopy(value, 0, out, 32 - value.length, value.length);
        }
        return out;
    }
}
