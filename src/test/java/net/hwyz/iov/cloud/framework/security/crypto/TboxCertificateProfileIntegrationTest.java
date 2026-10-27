package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EcdsaP1363;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoAutoConfiguration;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectReason;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofAlgorithm;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofVerificationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.VerifiedImportProof;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.EvidenceSource;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import net.hwyz.iov.cloud.framework.security.crypto.support.TboxProfileCertificates;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CR-017 集成测试：deriveAndWrap（CR-014）与 ImportProofVerifier（CR-016）共享统一
 * TBOX 设备证书 Profile 门禁与 leaf DER 摘要绑定（FW-SEC-DSN-CR-017 §7/§8/§12）。
 * <p>
 * 关键断言：
 * <ul>
 *   <li>Profile 拒绝时 Provider/ECDSA 调用恒为 0；</li>
 *   <li>统一 Profile 强制双 KU（单 KU 证书即使只走单路径也拒绝，RD-017-4）；</li>
 *   <li>证书绑定不匹配以 CERTIFICATE_BINDING_MISMATCH 在 ECDSA 前拒绝；</li>
 *   <li>wire 摘要保持 SHA-256(leafCertificateDER)（决策 1）。</li>
 * </ul>
 */
class TboxCertificateProfileIntegrationTest {

    private static final String VIN = "LSVAA4187N2123456";
    private static final String REQUEST_ID = "req-1";
    private static final String KEY_ID = "logical-v2c-uplink";
    private static final long VERSION = 7L;

    private final CryptoAutoConfiguration configuration = new CryptoAutoConfiguration();
    private final CryptoProperties properties = new CryptoProperties();
    private final CryptoMetrics cryptoMetrics = mock(CryptoMetrics.class);
    private final Clock clock = Clock.fixed(Instant.parse("2026-10-20T10:00:00Z"), ZoneOffset.UTC);
    private Environment environment;

    private KmsClient kmsClient;
    private DeviceResolver deviceResolver;
    private CertResolver certResolver;
    private CertificateEvidenceValidator evidenceValidator;
    private DefaultTboxDeviceCertificateValidator profileValidator;

    @BeforeEach
    void setUp() {
        properties.getKeyprov().getCertificateProfile().setEnabled(true);
        properties.getKeyprov().getCertificateProfile().setRequireTrustedChain(false);
        properties.getKeyprov().getCertificateProfile().setRequireGoodStatus(false);
        properties.getPki().getCertificateResolution().setEnabled(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem("unused-in-integration-tests");

        environment = mock(Environment.class);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(false);

        kmsClient = mock(KmsClient.class);
        deviceResolver = mock(DeviceResolver.class);
        certResolver = mock(CertResolver.class);
        evidenceValidator = configuration.certificateEvidenceValidator(
                new TestObjectProvider<>(), properties, new TestObjectProvider<>(clock));
        profileValidator = new DefaultTboxDeviceCertificateValidator(certResolver, evidenceValidator,
                properties, clock);
    }

    private void stubResolverWith(TboxProfileCertificates.Leaf leaf) throws Exception {
        when(certResolver.resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class)))
                .thenReturn(CertificateEvidenceValidator.fromCertificateDer(leaf.der(), EvidenceSource.PROVIDER_QUERY));
    }

    // ==================== CR-014 deriveAndWrap ====================

    @Test
    void deriveAndWrap_withProfile_positive_bindsLeafDerDigest() throws Exception {
        TboxProfileCertificates.Leaf leaf = TboxProfileCertificates.positive();
        stubResolverWith(leaf);
        DefaultKeyProvisioningTemplate template = new DefaultKeyProvisioningTemplate(
                kmsClient, cryptoMetrics, properties, deviceResolver, certResolver, evidenceValidator,
                profileValidator);
        when(kmsClient.deriveAndWrap(any(), any(), any(), any())).thenReturn(new DerivedWrappedKey(
                "logical-v2c-uplink", "ref", 1L, "v1",
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                new byte[]{1}, new byte[]{3}, new byte[]{2}, "op-1"));

        template.deriveAndWrap(BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate(serialOf(leaf)), DerivationContext.v1(), "op-1", "idem-1",
                "req-1", "V2C_COMM");

        byte[] leafDer = leaf.der();
        verify(kmsClient).deriveAndWrap(any(), any(),
                argThat(r -> r.mode() == WrapMode.DEVICE_CERT_PUBLIC_KEY
                        && r.certificateDer() != null && r.certificateDer().length > 0
                        && r.certificateSha256Fingerprint() != null
                        && r.spki() != null && r.spki().length > 0
                        && CanonicalEncoding.sha256(leafDer).length == 32),
                any());
        verify(kmsClient, org.mockito.Mockito.times(1)).deriveAndWrap(any(), any(), any(), any());
    }

    @Test
    void deriveAndWrap_profileReject_providerNeverCalled() throws Exception {
        TboxProfileCertificates.Leaf singleKu = TboxProfileCertificates.digitalSignatureOnly();
        stubResolverWith(singleKu);
        DefaultKeyProvisioningTemplate template = new DefaultKeyProvisioningTemplate(
                kmsClient, cryptoMetrics, properties, deviceResolver, certResolver, evidenceValidator,
                profileValidator);

        CertificateProfileRejectedException ex = assertThrows(CertificateProfileRejectedException.class,
                () -> template.deriveAndWrap(BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN),
                        KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate(serialOf(singleKu)),
                        DerivationContext.v1(), "op-1", "idem-1", "req-1", "V2C_COMM"));
        assertEquals(CertificateProfileRejectReason.KEY_AGREEMENT_MISSING, ex.rejectReason());
        verify(kmsClient, never()).deriveAndWrap(any(), any(), any(), any());
    }

    @Test
    void deriveAndWrap_caCertificate_profileRejectNotEndEntity() throws Exception {
        TboxProfileCertificates.Leaf ca = TboxProfileCertificates.caTrue();
        stubResolverWith(ca);
        DefaultKeyProvisioningTemplate template = new DefaultKeyProvisioningTemplate(
                kmsClient, cryptoMetrics, properties, deviceResolver, certResolver, evidenceValidator,
                profileValidator);

        CertificateProfileRejectedException ex = assertThrows(CertificateProfileRejectedException.class,
                () -> template.deriveAndWrap(BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN),
                        KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate(serialOf(ca)),
                        DerivationContext.v1(), "op-1", "idem-1", "req-1", "V2C_COMM"));
        assertEquals(CertificateProfileRejectReason.NOT_END_ENTITY, ex.rejectReason());
        verify(kmsClient, never()).deriveAndWrap(any(), any(), any(), any());
    }

    // ==================== CR-016 ImportProofVerifier ====================

    @Test
    void importProof_positiveProfile_verifiesWithLeafDerDigest() throws Exception {
        TboxProfileCertificates.Leaf leaf = TboxProfileCertificates.positive();
        stubResolverWith(leaf);
        DefaultImportProofVerifier verifier = new DefaultImportProofVerifier(
                certResolver, evidenceValidator, properties, cryptoMetrics, clock, profileValidator);

        byte[] envelopeDigest = CanonicalEncoding.sha256("envelope".getBytes(StandardCharsets.UTF_8));
        byte[] kcv = {0x0a, 0x0b, 0x0c};
        byte[] proofInput = net.hwyz.iov.cloud.framework.security.crypto.codec.ImportProofCanonical
                .proofInputV1(REQUEST_ID, "V2C_COMM", KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                        envelopeDigest, kcv);
        byte[] proof = signLowS(leaf, proofInput);

        ImportProofVerificationRequest request = new ImportProofVerificationRequest(
                ImportProofAlgorithm.ECDSA_P256_SHA256_P1363, proof,
                DeviceCertificateRef.ofCertificate(leaf.der()),
                CanonicalEncoding.sha256(leaf.der()), REQUEST_ID, "V2C_COMM",
                KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION, envelopeDigest, kcv);

        VerifiedImportProof result = verifier.verify(request);
        assertNotNull(result);
        assertArrayEquals(CanonicalEncoding.sha256(leaf.der()), result.certificateDigest(),
                "证书绑定摘要 = SHA-256(leafCertificateDER)，wire 摘要语义不变");
    }

    @Test
    void importProof_digestMismatch_rejectedAsBindingMismatchBeforeEcdsa() throws Exception {
        TboxProfileCertificates.Leaf leaf = TboxProfileCertificates.positive();
        stubResolverWith(leaf);
        DefaultImportProofVerifier verifier = new DefaultImportProofVerifier(
                certResolver, evidenceValidator, properties, cryptoMetrics, clock, profileValidator);

        byte[] envelopeDigest = CanonicalEncoding.sha256("envelope".getBytes(StandardCharsets.UTF_8));
        byte[] kcv = {0x0a, 0x0b, 0x0c};
        byte[] proofInput = net.hwyz.iov.cloud.framework.security.crypto.codec.ImportProofCanonical
                .proofInputV1(REQUEST_ID, "V2C_COMM", KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                        envelopeDigest, kcv);
        byte[] proof = signLowS(leaf, proofInput);
        byte[] wrongDigest = CanonicalEncoding.sha256("other-cert".getBytes(StandardCharsets.UTF_8));

        ImportProofVerificationRequest request = new ImportProofVerificationRequest(
                ImportProofAlgorithm.ECDSA_P256_SHA256_P1363, proof,
                DeviceCertificateRef.ofCertificate(leaf.der()), wrongDigest, REQUEST_ID, "V2C_COMM",
                KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION, envelopeDigest, kcv);

        CertificateProfileRejectedException ex = assertThrows(CertificateProfileRejectedException.class,
                () -> verifier.verify(request));
        assertEquals(CertificateProfileRejectReason.CERTIFICATE_BINDING_MISMATCH, ex.rejectReason(),
                "证书引用/摘要不一致须以 CERTIFICATE_BINDING_MISMATCH 在 ECDSA 前拒绝");
    }

    @Test
    void importProof_singleKuCertificate_profileRejectedEvenThoughOnlyDsNeeded() throws Exception {
        // RD-017-4：统一 Profile 强制双 KU；即使 import-proof 单路径只需要 digitalSignature，
        // 仅 digitalSignature 的证书也必须在 ECDSA 前拒绝。
        TboxProfileCertificates.Leaf singleKu = TboxProfileCertificates.digitalSignatureOnly();
        stubResolverWith(singleKu);
        DefaultImportProofVerifier verifier = new DefaultImportProofVerifier(
                certResolver, evidenceValidator, properties, cryptoMetrics, clock, profileValidator);

        byte[] envelopeDigest = CanonicalEncoding.sha256("envelope".getBytes(StandardCharsets.UTF_8));
        byte[] kcv = {0x0a, 0x0b, 0x0c};
        byte[] proofInput = net.hwyz.iov.cloud.framework.security.crypto.codec.ImportProofCanonical
                .proofInputV1(REQUEST_ID, "V2C_COMM", KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                        envelopeDigest, kcv);
        byte[] proof = signLowS(singleKu, proofInput);

        ImportProofVerificationRequest request = new ImportProofVerificationRequest(
                ImportProofAlgorithm.ECDSA_P256_SHA256_P1363, proof,
                DeviceCertificateRef.ofCertificate(singleKu.der()),
                CanonicalEncoding.sha256(singleKu.der()), REQUEST_ID, "V2C_COMM",
                KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION, envelopeDigest, kcv);

        CertificateProfileRejectedException ex = assertThrows(CertificateProfileRejectedException.class,
                () -> verifier.verify(request));
        assertEquals(CertificateProfileRejectReason.KEY_AGREEMENT_MISSING, ex.rejectReason(),
                "统一 Profile 强制双 KU（RD-017-4）");
    }

    @Test
    void importProof_withoutProfile_legacySingleKuPathStillWorks() throws Exception {
        // 未装配 Profile 时保持既有 import-proof 行为（向后兼容，独立装配决策 3）。
        TboxProfileCertificates.Leaf singleKu = TboxProfileCertificates.digitalSignatureOnly();
        when(certResolver.resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class)))
                .thenReturn(CertificateEvidenceValidator.fromCertificateDer(
                        singleKu.der(), EvidenceSource.PROVIDER_QUERY));
        properties.getImportProof().getCertificate().setRequireGoodStatus(false);
        properties.getImportProof().getCertificate().setRequireTrustedChain(false);
        DefaultImportProofVerifier verifier = new DefaultImportProofVerifier(
                certResolver, evidenceValidator, properties, cryptoMetrics, clock, null);

        byte[] envelopeDigest = CanonicalEncoding.sha256("envelope".getBytes(StandardCharsets.UTF_8));
        byte[] kcv = {0x0a, 0x0b, 0x0c};
        byte[] proofInput = net.hwyz.iov.cloud.framework.security.crypto.codec.ImportProofCanonical
                .proofInputV1(REQUEST_ID, "V2C_COMM", KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION,
                        envelopeDigest, kcv);
        byte[] proof = signLowS(singleKu, proofInput);

        ImportProofVerificationRequest request = new ImportProofVerificationRequest(
                ImportProofAlgorithm.ECDSA_P256_SHA256_P1363, proof,
                DeviceCertificateRef.ofCertificate(singleKu.der()),
                CanonicalEncoding.sha256(singleKu.der()), REQUEST_ID, "V2C_COMM",
                KeyPurpose.UPLINK_AEAD, KEY_ID, VERSION, envelopeDigest, kcv);

        VerifiedImportProof result = verifier.verify(request);
        assertNotNull(result);
        assertTrue(result.certificateDigest().length == 32);
    }

    private static String serialOf(TboxProfileCertificates.Leaf leaf) {
        return leaf.certificate().getSerialNumber().toString(16);
    }

    private static byte[] signLowS(TboxProfileCertificates.Leaf leaf, byte[] proofInput) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(leaf.keyPair().getPrivate());
        signature.update(proofInput);
        return EcdsaP1363.derToP1363(signature.sign());
    }
}
