package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoAutoConfiguration;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectReason;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceCertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.ValidatedTboxDeviceCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import net.hwyz.iov.cloud.framework.security.crypto.support.TboxProfileCertificates;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 统一 TBOX 设备证书 Profile 验证器测试（FW-SEC-DSN-CR-017 §5/§12）。
 * <p>
 * 覆盖全正负向矩阵：CA=false、P-256、双 KU、clientAuth-only EKU、关键扩展、身份绑定、
 * leaf DER digest、状态 freshness 与敏感扫描。
 */
class DefaultTboxDeviceCertificateValidatorTest {

    private final CryptoAutoConfiguration configuration = new CryptoAutoConfiguration();
    private final CryptoProperties properties = new CryptoProperties();
    private final CryptoMetrics cryptoMetrics = mock(CryptoMetrics.class);
    private final Clock clock = Clock.fixed(Instant.parse("2026-10-20T10:00:00Z"), ZoneOffset.UTC);
    private Environment environment;

    private DefaultTboxDeviceCertificateValidator validator;
    private CertificateEvidenceValidator evidenceValidator;
    private CertResolver certResolver;

    @BeforeEach
    void setUp() {
        properties.getPki().getCertificateResolution().setEnabled(true);
        properties.getPki().getCertificateResolution().setTrustAnchorsPem("unused-in-structural-tests");
        properties.getPki().getCertificateResolution().getBusinessKeyWrap().setRequireGoodStatus(false);
        properties.getKeyprov().getCertificateProfile().setRequireTrustedChain(false);
        properties.getKeyprov().getCertificateProfile().setRequireGoodStatus(false);

        environment = mock(Environment.class);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(false);

        certResolver = configuration.certResolver(properties, cryptoMetrics,
                new TestObjectProvider<>(), new TestObjectProvider<>(), new TestObjectProvider<>(),
                new TestObjectProvider<>(), environment);
        evidenceValidator = configuration.certificateEvidenceValidator(
                new TestObjectProvider<>(), properties, new TestObjectProvider<>(clock));
        validator = new DefaultTboxDeviceCertificateValidator(certResolver, evidenceValidator,
                properties, clock);
    }

    // ==================== 正向 ====================

    @Test
    void positiveProfile_validates() throws Exception {
        TboxProfileCertificates.Leaf leaf = TboxProfileCertificates.positive();
        ValidatedTboxDeviceCertificate validated = validator.validate(
                DeviceCertificateRef.ofCertificate(leaf.der()), DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1);

        assertNotNull(validated);
        assertEquals(DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1, validated.profile());
        assertTrue(validated.p256());
        assertTrue(validated.digitalSignature());
        assertTrue(validated.keyAgreement());
        assertTrue(validated.clientAuth());
        assertEquals(clock.instant(), validated.validatedAt());
        assertNull(validated.statusFreshUntil(), "requireGoodStatus=false 时 freshness 为 null（不可缓存）");
        assertArrayEquals(CanonicalEncoding.sha256(leaf.der()), validated.certificatePolicyDigest(),
                "证书绑定摘要 = SHA-256(leafCertificateDER)，wire 摘要语义不变");
        assertNotNull(validated.publicKey());
        assertNotNull(validated.certificateRef());
    }

    @Test
    void positiveProfile_digestDefensiveCopy() throws Exception {
        TboxProfileCertificates.Leaf leaf = TboxProfileCertificates.positive();
        ValidatedTboxDeviceCertificate validated = validator.validate(
                DeviceCertificateRef.ofCertificate(leaf.der()), DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1);

        byte[] digest = validated.certificatePolicyDigest();
        digest[0] ^= 0x01;
        assertArrayEquals(CanonicalEncoding.sha256(leaf.der()), validated.certificatePolicyDigest(),
                "访问返回副本，外部篡改不影响内部状态");
    }

    @Test
    void statusFreshUntil_usesNextUpdate() throws Exception {
        properties.getKeyprov().getCertificateProfile().setRequireGoodStatus(true);
        when(environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false))
                .thenReturn(true);
        Instant nextUpdate = Instant.parse("2026-10-21T10:00:00Z");
        net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient pkiClient =
                mock(net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient.class);
        when(pkiClient.checkCertificateStatus(org.mockito.ArgumentMatchers.any()))
                .thenReturn(new net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient.CertificateStatusResult(
                        net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient.RevocationState.GOOD,
                        "TBOX-test", Instant.parse("2026-10-19T10:00:00Z"), nextUpdate,
                        Instant.parse("2026-10-20T09:00:00Z"), nextUpdate,
                        net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient.RevocationSource.OCSP,
                        clock.instant()));

        CertResolver statusResolver = configuration.certResolver(properties, cryptoMetrics,
                new TestObjectProvider<>(), new TestObjectProvider<>(), new TestObjectProvider<>(pkiClient),
                new TestObjectProvider<>(), environment);
        CertificateEvidenceValidator statusValidator = configuration.certificateEvidenceValidator(
                new TestObjectProvider<>(pkiClient), properties, new TestObjectProvider<>(clock));
        DefaultTboxDeviceCertificateValidator statusProfileValidator =
                new DefaultTboxDeviceCertificateValidator(statusResolver, statusValidator, properties, clock);

        TboxProfileCertificates.Leaf leaf = TboxProfileCertificates.positive();
        ValidatedTboxDeviceCertificate validated = statusProfileValidator.validate(
                DeviceCertificateRef.ofCertificate(leaf.der()),
                DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1);
        assertEquals(nextUpdate, validated.statusFreshUntil(), "statusFreshUntil 取 status 响应 nextUpdate");
    }

    // ==================== 负向矩阵 ====================

    @Test
    void caTrue_rejectedNotEndEntity() throws Exception {
        assertProfileReject(TboxProfileCertificates.caTrue(),
                CertificateProfileRejectReason.NOT_END_ENTITY);
    }

    @Test
    void rsa_rejectedPublicKeyAlgorithm() throws Exception {
        assertProfileReject(TboxProfileCertificates.rsa(),
                CertificateProfileRejectReason.PUBLIC_KEY_ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void p384_rejectedCurve() throws Exception {
        assertProfileReject(TboxProfileCertificates.p384(),
                CertificateProfileRejectReason.CURVE_NOT_ALLOWED);
    }

    @Test
    void digitalSignatureOnly_rejectedKeyAgreementMissing() throws Exception {
        assertProfileReject(TboxProfileCertificates.digitalSignatureOnly(),
                CertificateProfileRejectReason.KEY_AGREEMENT_MISSING);
    }

    @Test
    void keyAgreementOnly_rejectedDigitalSignatureMissing() throws Exception {
        assertProfileReject(TboxProfileCertificates.keyAgreementOnly(),
                CertificateProfileRejectReason.DIGITAL_SIGNATURE_MISSING);
    }

    @Test
    void extraKuBit_rejectedProfileNotAllowed() throws Exception {
        assertProfileReject(TboxProfileCertificates.extraKuBit(),
                CertificateProfileRejectReason.PROFILE_NOT_ALLOWED);
    }

    @Test
    void kuNonCritical_rejectedProfileNotAllowed() throws Exception {
        assertProfileReject(TboxProfileCertificates.kuNonCritical(),
                CertificateProfileRejectReason.PROFILE_NOT_ALLOWED);
    }

    @Test
    void noEku_rejectedClientAuthMissing() throws Exception {
        assertProfileReject(TboxProfileCertificates.noEku(),
                CertificateProfileRejectReason.CLIENT_AUTH_MISSING);
    }

    @Test
    void serverAuthEku_rejectedEkuPolicyConflict() throws Exception {
        assertProfileReject(TboxProfileCertificates.serverAuthEku(),
                CertificateProfileRejectReason.EKU_POLICY_CONFLICT);
    }

    @Test
    void anyEku_rejectedEkuPolicyConflict() throws Exception {
        assertProfileReject(TboxProfileCertificates.anyEku(),
                CertificateProfileRejectReason.EKU_POLICY_CONFLICT);
    }

    @Test
    void noIdentity_rejectedIdentityBindingInvalid() throws Exception {
        assertProfileReject(TboxProfileCertificates.noIdentity(),
                CertificateProfileRejectReason.IDENTITY_BINDING_INVALID);
    }

    @Test
    void unknownCriticalExtension_rejectedUnsupportedCriticalExtension() throws Exception {
        assertProfileReject(TboxProfileCertificates.unknownCriticalExtension(),
                CertificateProfileRejectReason.UNSUPPORTED_CRITICAL_EXTENSION);
    }

    @Test
    void expiredCertificate_rejectedStatusKeepsEvidenceSurface() throws Exception {
        TboxProfileCertificates.Leaf leaf = TboxProfileCertificates.expired();
        CertificateEvidenceRejectedException ex = assertThrows(CertificateEvidenceRejectedException.class,
                () -> validator.validate(DeviceCertificateRef.ofCertificate(leaf.der()),
                        DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1));
        assertEquals(CertificateEvidenceRejectedException.Reason.CERTIFICATE_EXPIRED, ex.rejectReason());
        assertFalse(ex.isRetryable(), "状态类拒绝不可重试");
    }

    @Test
    void evaluateProfile_staticPositiveAndReasonMapping() throws Exception {
        TboxProfileCertificates.Leaf positive = TboxProfileCertificates.positive();
        DefaultTboxDeviceCertificateValidator.ProfileSemantics semantics =
                DefaultTboxDeviceCertificateValidator.evaluateProfile(
                        positive.certificate(), DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1);
        assertTrue(semantics.p256());
        assertTrue(semantics.digitalSignature());
        assertTrue(semantics.keyAgreement());
        assertTrue(semantics.clientAuth());
    }

    // ==================== 敏感扫描 ====================

    @Test
    void rejectionMessage_doesNotLeakCertificateMaterial() throws Exception {
        TboxProfileCertificates.Leaf leaf = TboxProfileCertificates.caTrue();
        CertificateProfileRejectedException ex = assertThrows(CertificateProfileRejectedException.class,
                () -> validator.validate(DeviceCertificateRef.ofCertificate(leaf.der()),
                        DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1));
        String message = ex.getMessage();
        String serialHex = leaf.certificate().getSerialNumber().toString(16).toLowerCase();
        assertFalse(message.contains(serialHex), "异常不得泄漏 serial");
        assertFalse(message.contains("TBOX-"), "异常不得泄漏设备身份");
        assertFalse(message.contains(org.bouncycastle.util.encoders.Hex.toHexString(
                leaf.certificate().getPublicKey().getEncoded())), "异常不得泄漏公钥编码");
    }

    @Test
    void validatedResult_toString_doesNotLeakMaterial() throws Exception {
        TboxProfileCertificates.Leaf leaf = TboxProfileCertificates.positive();
        ValidatedTboxDeviceCertificate validated = validator.validate(
                DeviceCertificateRef.ofCertificate(leaf.der()), DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1);
        String str = validated.toString();
        assertFalse(str.contains(CanonicalEncoding.hexLower(leaf.der())), "toString 不得泄漏 DER");
        assertFalse(str.contains(leaf.certificate().getSerialNumber().toString(16)), "toString 不得泄漏 serial");
        assertFalse(str.contains("TBOX-"), "toString 不得泄漏设备身份");
        assertFalse(str.contains(CanonicalEncoding.hexLower(validated.certificatePolicyDigest())),
                "toString 不得泄漏完整摘要");
    }

    // ==================== 工具 ====================

    private void assertProfileReject(TboxProfileCertificates.Leaf leaf, CertificateProfileRejectReason expected)
            throws Exception {
        CertificateProfileRejectedException ex = assertThrows(CertificateProfileRejectedException.class,
                () -> validator.validate(DeviceCertificateRef.ofCertificate(leaf.der()),
                        DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1));
        assertEquals(expected, ex.rejectReason());
        assertFalse(ex.isRetryable(), "Profile 策略拒绝不可重试");
    }
}
