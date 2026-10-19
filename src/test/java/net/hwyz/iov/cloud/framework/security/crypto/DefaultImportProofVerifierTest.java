package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EcdsaP1363;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.ImportProofRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofAlgorithm;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofRejectReason;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofVerificationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.VerifiedImportProof;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.EvidenceSource;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import net.hwyz.iov.cloud.framework.security.crypto.support.ImportProofFixture;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * {@link DefaultImportProofVerifier} 验证流水线与错误模型单元测试（FW-SEC-DSN-CR-016 §4/§6/§7/§9）。
 */
class DefaultImportProofVerifierTest {

    private static final String REQUEST_ID = "req-1";
    private static final String KEY_ID = "logical-v2c-uplink";
    private static final long VERSION = 7L;
    private static final byte[] KCV = {0x0a, 0x0b, 0x0c};
    private static final Instant NOW = Instant.parse("2026-10-19T00:00:00Z");

    private CryptoProperties properties;
    private CertResolver certResolver;
    private CertificateEvidenceValidator evidenceValidator;
    private ImportProofFixture.Material material;
    private DefaultImportProofVerifier verifier;
    private byte[] envelopeDigest;

    @BeforeEach
    void setUp() throws Exception {
        properties = new CryptoProperties();
        properties.getImportProof().setEnabled(true);
        properties.getImportProof().getCertificate().setRequireTrustedChain(false);
        properties.getImportProof().getCertificate().setRequireGoodStatus(false);

        material = ImportProofFixture.deviceCertificate(NOW);
        envelopeDigest = CanonicalEncoding.sha256("envelope".getBytes(StandardCharsets.UTF_8));

        certResolver = mock(CertResolver.class);
        stubResolve(material.certificateDer());
        evidenceValidator = new CertificateEvidenceValidator(new TestObjectProvider<>(),
                properties, Clock.fixed(NOW, ZoneOffset.UTC));
        verifier = new DefaultImportProofVerifier(certResolver, evidenceValidator, properties, null,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private void stubResolve(byte[] leafDer) {
        when(certResolver.resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class)))
                .thenReturn(CertificateEvidenceValidator.fromCertificateDer(leafDer, EvidenceSource.INLINE_DER));
    }

    private byte[] validProof(String requestId, KeyPurpose purpose, String keyId, long version,
                              byte[] expectedEnvelopeDigest, byte[] kcv) throws Exception {
        byte[] proofInput = ImportProofFixture.proofInput(requestId, purpose, keyId, version,
                expectedEnvelopeDigest, kcv);
        return ImportProofFixture.signLowS(material.keyPair(), proofInput);
    }

    private ImportProofVerificationRequest request(byte[] proof, byte[] expectedDigest,
                                                   String requestId, String businessDomain,
                                                   KeyPurpose purpose, String keyId, long version,
                                                   byte[] envDigest, byte[] kcv) {
        return new ImportProofVerificationRequest(ImportProofAlgorithm.ECDSA_P256_SHA256_P1363, proof,
                DeviceCertificateRef.ofCertificate(material.certificateDer()), expectedDigest,
                requestId, businessDomain, purpose, keyId, version, envDigest, kcv);
    }

    private ImportProofVerificationRequest validRequest() throws Exception {
        return request(validProof(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                        envelopeDigest, KCV), material.certificateDigest(), REQUEST_ID,
                ImportProofFixture.BUSINESS_DOMAIN, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                envelopeDigest, KCV);
    }

    @Test
    void verify_validProof_returnsMinimalResult() throws Exception {
        VerifiedImportProof result = verifier.verify(validRequest());

        assertEquals(ImportProofAlgorithm.ECDSA_P256_SHA256_P1363, result.proofAlgorithm());
        assertArrayEquals(material.certificateDigest(), result.certificateDigest());
        assertEquals(KeyPurpose.UPLINK_AEAD, result.purpose());
        assertEquals(32, result.proofInputDigest().length);
        assertEquals(NOW, result.verifiedAt());
    }

    @Test
    void verify_repeatableWithoutSideEffects() throws Exception {
        ImportProofVerificationRequest request = validRequest();
        VerifiedImportProof first = verifier.verify(request);
        VerifiedImportProof second = verifier.verify(request);

        assertArrayEquals(first.certificateDigest(), second.certificateDigest());
        assertArrayEquals(first.proofInputDigest(), second.proofInputDigest());
        assertEquals(first.verifiedAt(), second.verifiedAt());
    }

    @Test
    void verify_tamperedGovernedField_signatureInvalid() throws Exception {
        // proof 基于 version=7，但请求声明 version=8 → 重建 canonical 后验签失败。
        byte[] proof = validProof(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                envelopeDigest, KCV);
        ImportProofVerificationRequest tampered = request(proof, material.certificateDigest(),
                REQUEST_ID, ImportProofFixture.BUSINESS_DOMAIN, KeyPurpose.UPLINK_AEAD, KEY_ID,
                VERSION + 1, envelopeDigest, KCV);

        ImportProofRejectedException ex = assertThrows(ImportProofRejectedException.class,
                () -> verifier.verify(tampered));
        assertEquals(ImportProofRejectReason.SIGNATURE_INVALID, ex.rejectReason());
        assertFalse(ex.isRetryable());
    }

    @Test
    void verify_highS_rejected() throws Exception {
        byte[] highS = validProof(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                envelopeDigest, KCV).clone();
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(highS, 32, 64));
        byte[] normalized = leftPad32(EcdsaP1363.P256_ORDER_N.subtract(s).toByteArray());
        System.arraycopy(normalized, 0, highS, 32, 32);

        ImportProofRejectedException ex = assertThrows(ImportProofRejectedException.class,
                () -> verifier.verify(request(highS, material.certificateDigest(), REQUEST_ID,
                        ImportProofFixture.BUSINESS_DOMAIN, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                        envelopeDigest, KCV)));
        assertEquals(ImportProofRejectReason.HIGH_S, ex.rejectReason());
    }

    @Test
    void verify_wrongProofLength_rejected() throws Exception {
        ImportProofRejectedException ex = assertThrows(ImportProofRejectedException.class,
                () -> verifier.verify(request(new byte[63], material.certificateDigest(), REQUEST_ID,
                        ImportProofFixture.BUSINESS_DOMAIN, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                        envelopeDigest, KCV)));
        assertEquals(ImportProofRejectReason.INVALID_LENGTH, ex.rejectReason());
    }

    @Test
    void verify_unknownAlgorithm_rejected() throws Exception {
        ImportProofVerificationRequest request = new ImportProofVerificationRequest(null,
                validProof(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION, envelopeDigest, KCV),
                DeviceCertificateRef.ofCertificate(material.certificateDer()),
                material.certificateDigest(), REQUEST_ID, ImportProofFixture.BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION, envelopeDigest, KCV);

        ImportProofRejectedException ex = assertThrows(ImportProofRejectedException.class,
                () -> verifier.verify(request));
        assertEquals(ImportProofRejectReason.ALGORITHM_NOT_ALLOWED, ex.rejectReason());
    }

    @Test
    void verify_certificateDigestMismatch_rejected() throws Exception {
        ImportProofRejectedException ex = assertThrows(ImportProofRejectedException.class,
                () -> verifier.verify(request(validProof(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID,
                                VERSION, envelopeDigest, KCV), new byte[32], REQUEST_ID,
                        ImportProofFixture.BUSINESS_DOMAIN, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                        envelopeDigest, KCV)));
        assertEquals(ImportProofRejectReason.CERTIFICATE_DIGEST_MISMATCH, ex.rejectReason());
    }

    @Test
    void verify_disallowedBusinessDomain_contextInvalid() throws Exception {
        for (String domain : new String[]{"V2C_COMM_ROOT", "v2c_comm", "V2C_COMM_ROOT_ALIAS"}) {
            ImportProofRejectedException ex = assertThrows(ImportProofRejectedException.class,
                    () -> verifier.verify(request(validProof(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID,
                                    VERSION, envelopeDigest, KCV), material.certificateDigest(), REQUEST_ID,
                            domain, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                            envelopeDigest, KCV)));
            assertEquals(ImportProofRejectReason.CONTEXT_INVALID, ex.rejectReason(),
                    "businessDomain=" + domain + " 必须 fail-closed");
        }
    }

    @Test
    void verify_blankRequestId_contextInvalid() throws Exception {
        ImportProofRejectedException ex = assertThrows(ImportProofRejectedException.class,
                () -> verifier.verify(request(validProof(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID,
                                VERSION, envelopeDigest, KCV), material.certificateDigest(), "  ",
                        ImportProofFixture.BUSINESS_DOMAIN, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                        envelopeDigest, KCV)));
        assertEquals(ImportProofRejectReason.CONTEXT_INVALID, ex.rejectReason());
    }

    @Test
    void verify_spkiOnlyEvidence_dependencyUnavailableRetryable() throws Exception {
        when(certResolver.resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class)))
                .thenReturn(CertificateEvidenceValidator.fromSpki(
                        material.keyPair().getPublic().getEncoded(), null, EvidenceSource.INLINE_SPKI));

        CertificateMaterialUnavailableException ex = assertThrows(CertificateMaterialUnavailableException.class,
                () -> verifier.verify(validRequest()));
        assertTrue(ex.isRetryable(), "缺证书 DER 属材料暂不可用，可重试（CR-016 §7）");
    }

    @Test
    void verify_nonP256Certificate_policyRejectedNotRetryable() throws Exception {
        java.security.KeyPair p384 = TestPkiMaterial.generateKeyPair("secp384r1");
        X509Certificate leaf = TestPkiMaterial.issueEndEntitySelfSigned(
                new X500Name("CN=p384"), p384, BigInteger.valueOf(11L), KeyUsage.digitalSignature,
                NOW.minusSeconds(3600), NOW.plusSeconds(3600));
        stubResolve(leaf.getEncoded());

        CertificateEvidenceRejectedException ex = assertThrows(CertificateEvidenceRejectedException.class,
                () -> verifier.verify(validRequest()));
        assertEquals(CertificateEvidenceRejectedException.Reason.CURVE_NOT_ALLOWED, ex.rejectReason());
        assertFalse(ex.isRetryable());
    }

    @Test
    void verify_missingDigitalSignature_policyRejectedNotRetryable() throws Exception {
        java.security.KeyPair keyPair = TestPkiMaterial.generateKeyPair();
        X509Certificate leaf = TestPkiMaterial.issueEndEntitySelfSigned(
                new X500Name("CN=no-dsig"), keyPair, BigInteger.valueOf(12L), KeyUsage.keyAgreement,
                NOW.minusSeconds(3600), NOW.plusSeconds(3600));
        stubResolve(leaf.getEncoded());

        CertificateEvidenceRejectedException ex = assertThrows(CertificateEvidenceRejectedException.class,
                () -> verifier.verify(validRequest()));
        assertEquals(CertificateEvidenceRejectedException.Reason.KEY_USAGE_NOT_PERMITTED, ex.rejectReason());
        assertFalse(ex.isRetryable());
    }

    @Test
    void verify_recordsMetricsWithoutSensitiveTags() throws Exception {
        CryptoMetrics metrics = mock(CryptoMetrics.class);
        DefaultImportProofVerifier metered = new DefaultImportProofVerifier(certResolver,
                evidenceValidator, properties, metrics, Clock.fixed(NOW, ZoneOffset.UTC));

        metered.verify(validRequest());
        verify(metrics).recordImportProofVerify(anyLong());

        byte[] proof = validProof(REQUEST_ID, KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                envelopeDigest, KCV);
        assertThrows(ImportProofRejectedException.class, () -> metered.verify(request(proof,
                material.certificateDigest(), REQUEST_ID, ImportProofFixture.BUSINESS_DOMAIN,
                KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION + 1, envelopeDigest, KCV)));
        verify(metrics).recordImportProofRejection(eq("SIGNATURE_INVALID"));

        Mockito.reset(metrics);
        when(certResolver.resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class)))
                .thenReturn(CertificateEvidenceValidator.fromSpki(
                        material.keyPair().getPublic().getEncoded(), null, EvidenceSource.INLINE_SPKI));
        assertThrows(CertificateMaterialUnavailableException.class, () -> metered.verify(validRequest()));
        verify(metrics).recordImportProofDependencyUnavailable();
    }

    @Test
    void verify_toStringDoesNotLeakProofMaterial() throws Exception {
        ImportProofVerificationRequest request = validRequest();
        String text = request.toString();
        assertFalse(text.contains(CanonicalEncoding.hexLower(request.importProof())));
        assertFalse(text.contains(KEY_ID));
        assertFalse(text.contains(CanonicalEncoding.hexLower(material.certificateDigest())));
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
