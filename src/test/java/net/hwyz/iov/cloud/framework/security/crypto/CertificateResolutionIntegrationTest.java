package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsKeyReference;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsRecipient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.EnrollmentRecord;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceMismatchException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateReferenceAmbiguousException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateLocator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateReferenceDirectory;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultCertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.EvidenceSource;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 证书材料解析端到端集成测试（FW-SEC-DSN-CR-012 §7/§10）。
 * <p>
 * 以真实 {@link DefaultCertResolver} + {@link CertificateEvidenceValidator} +
 * {@link DefaultBusinessKeyMaterialTemplate} 装配，覆盖设计 §10 测试矩阵。
 */
class CertificateResolutionIntegrationTest {

    private CryptoProperties properties;
    private KmsClient kmsClient;
    private CryptoMetrics cryptoMetrics;
    private CertificateEnrollmentResultStore resultStore;
    private CertEnrollmentTemplate enrollmentTemplate;
    private PkiClient pkiClient;
    private TestPkiMaterial.Pki pki;

    @BeforeEach
    void setUp() throws Exception {
        pki = TestPkiMaterial.generate();
        properties = new CryptoProperties();
        properties.getProvisioning().setProvider("openbao-business-key");
        CryptoProperties.Pki.CertificateResolution config = properties.getPki().getCertificateResolution();
        config.setEnabled(true);
        config.setProviderQueryEnabled(true);
        config.setDomainDirectoryEnabled(true);
        config.setTrustAnchorsPem(TestPkiMaterial.pem("CERTIFICATE", pki.intermediateCert().getEncoded()));
        config.getBusinessKeyWrap().setRequireCertificate(true);
        config.getBusinessKeyWrap().setRequireTrustedChain(true);
        config.getBusinessKeyWrap().setRequireGoodStatus(false);

        kmsClient = mock(KmsClient.class);
        cryptoMetrics = mock(CryptoMetrics.class);
        resultStore = mock(CertificateEnrollmentResultStore.class);
        enrollmentTemplate = mock(CertEnrollmentTemplate.class);
        pkiClient = mock(PkiClient.class);

        when(kmsClient.wrapKey(any(KmsKeyReference.class), any(KmsRecipient.class), anyString(), anyString()))
                .thenReturn(new KmsWrappedKey(new byte[]{7, 7, 7}, "k-1", 1, "ECDH-ES", null, null));
    }

    private CertificateEnrollmentResultStore store() {
        return resultStore;
    }

    private DefaultBusinessKeyMaterialTemplate template(
            ObjectProvider<CertificateReferenceDirectory> directories, PkiClient statusClient) {
        CertificateEvidenceValidator validator =
                new CertificateEvidenceValidator(new TestObjectProvider<>(statusClient), properties);
        CertResolver resolver = new DefaultCertResolver(
                new TestObjectProvider<>(store()),
                new TestObjectProvider<>(enrollmentTemplate),
                new TestObjectProvider<>(pkiClient),
                directories,
                properties);
        return new DefaultBusinessKeyMaterialTemplate(kmsClient, cryptoMetrics, properties, resolver, validator);
    }

    private DefaultBusinessKeyMaterialTemplate template() {
        return template(new TestObjectProvider<>(), pkiClient);
    }

    private EnrollmentRecord record(EnrollmentState state) throws Exception {
        return new EnrollmentRecord("req-1", "caller", "idem-1", new byte[]{1}, "csr-hash", "TBOX_TSP_CLIENT",
                state, pki.leafCert().getSerialNumber().toString(16), pki.leafCert().getEncoded(),
                List.of(pki.intermediateCert().getEncoded(), pki.rootCert().getEncoded()),
                null, null, null, null, Instant.now(), Instant.now());
    }

    private BusinessKeyRef keyRef() {
        return new BusinessKeyRef("k-1", "bk/k-1");
    }

    private WrapContext context() {
        return new WrapContext(WrapMode.DEVICE_CERT_PUBLIC_KEY, "idem-w", null);
    }

    private String serial() {
        return pki.leafCert().getSerialNumber().toString(16);
    }

    private TestObjectProvider<CertificateReferenceDirectory> dirs(CertificateReferenceDirectory... directories) {
        return new TestObjectProvider<>(directories);
    }

    @Test
    void inlineDerWithTrustedChain_success() throws Exception {
        RecipientRef recipient = RecipientRef.DeviceCertificate.ofCertificate(pki.leafCert().getEncoded());

        var wrapped = template().wrap(keyRef(), recipient, context());

        assertNotNull(wrapped);
        assertArrayEquals(new byte[]{7, 7, 7}, wrapped.wrapped());
    }

    @Test
    void inlineDerFingerprintMismatch_rejected() throws Exception {
        RecipientRef recipient = new RecipientRef.DeviceCertificate(null, null,
                pki.leafCert().getEncoded(), null, "deadbeef", null);

        assertThrows(CertificateEvidenceMismatchException.class,
                () -> template().wrap(keyRef(), recipient, context()));
    }

    @Test
    void requestIdIssuedFromStore_success() throws Exception {
        when(resultStore.findByRequestId("req-1")).thenReturn(Optional.of(record(EnrollmentState.ISSUED)));
        RecipientRef recipient = RecipientRef.DeviceCertificate.ofRequestId("req-1");

        assertNotNull(template().wrap(keyRef(), recipient, context()));
    }

    @Test
    void stepCaSerialViaVmdDirectory_success() throws Exception {
        properties.getPki().setProvider("step-ca");
        when(resultStore.findByRequestId("req-1")).thenReturn(Optional.of(record(EnrollmentState.ISSUED)));
        CertificateReferenceDirectory directory =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-1"));

        RecipientRef recipient = new RecipientRef.DeviceCertificate(serial());
        assertNotNull(template(dirs(directory), pkiClient).wrap(keyRef(), recipient, context()));
    }

    @Test
    void legacyProviderSerialQuery_success() throws Exception {
        when(pkiClient.queryCertificate(serial())).thenReturn(new PkiClient.CertificateResponse(
                "req-1", pki.leafCert().getEncoded(), null, serial(), null, null));

        RecipientRef recipient = new RecipientRef.DeviceCertificate(serial());
        assertNotNull(template().wrap(keyRef(), recipient, context()));
    }

    @Test
    void onlyFingerprint_failClosed() {
        RecipientRef recipient = new RecipientRef.DeviceCertificate(null, null, null, null, "abc", null);

        assertThrows(CertificateMaterialUnavailableException.class,
                () -> template().wrap(keyRef(), recipient, context()));
    }

    @Test
    void multipleDirectoriesDifferentLocators_rejected() {
        CertificateReferenceDirectory first =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-1"));
        CertificateReferenceDirectory second =
                ref -> Optional.of(new CertificateLocator.EnrollmentRequest("req-2"));

        RecipientRef recipient = new RecipientRef.DeviceCertificate(serial());
        assertThrows(CertificateReferenceAmbiguousException.class,
                () -> template(dirs(first, second), pkiClient).wrap(keyRef(), recipient, context()));
    }

    @Test
    void revokedStatus_failClosed() throws Exception {
        properties.getPki().getCertificateResolution().getBusinessKeyWrap().setRequireGoodStatus(true);
        when(pkiClient.checkCertificateStatus(any())).thenReturn(status(
                PkiClient.RevocationState.REVOKED));
        RecipientRef recipient = RecipientRef.DeviceCertificate.ofCertificate(pki.leafCert().getEncoded());

        CertificateMaterialUnavailableException ex = assertThrows(CertificateMaterialUnavailableException.class,
                () -> template(new TestObjectProvider<>(), pkiClient).wrap(keyRef(), recipient, context()));
        assertTrue(ex.getMessage().contains("REVOKED"));
    }

    @Test
    void customResolverUnvalidatedMaterial_rejectedByPublicValidator() throws Exception {
        // 自定义 Resolver 返回与声明 serial 不一致的未校验材料，公共 Validator 必须拒绝
        TestPkiMaterial.Pki other = TestPkiMaterial.generate();
        byte[] otherDer = other.leafCert().getEncoded();
        CertResolver custom = new CertResolver() {
            @Override
            public byte[] resolveByVin(String vin) {
                return otherDer;
            }

            @Override
            public byte[] resolveByDeviceSn(String deviceSn) {
                return otherDer;
            }

            @Override
            public byte[] resolveByUid(String uid) {
                return otherDer;
            }

            @Override
            public byte[] resolveBySerial(String certSerial) {
                return otherDer;
            }

            @Override
            public CertificateEvidence resolve(DeviceCertificateRef ref, CertificateResolvePolicy policy) {
                return CertificateEvidenceValidator.fromCertificateDer(
                        otherDer, List.of(), EvidenceSource.PROVIDER_QUERY);
            }
        };
        CertificateEvidenceValidator validator =
                new CertificateEvidenceValidator(new TestObjectProvider<>(pkiClient), properties);
        DefaultBusinessKeyMaterialTemplate template =
                new DefaultBusinessKeyMaterialTemplate(kmsClient, cryptoMetrics, properties, custom, validator);
        RecipientRef recipient = new RecipientRef.DeviceCertificate("deadbeef");

        assertThrows(CertificateEvidenceMismatchException.class,
                () -> template.wrap(keyRef(), recipient, context()));
    }

    private PkiClient.CertificateStatusResult status(PkiClient.RevocationState state) {
        return new PkiClient.CertificateStatusResult(state, "TBOX-test",
                pki.leafCert().getNotBefore().toInstant(), pki.leafCert().getNotAfter().toInstant(),
                Instant.now(), null, PkiClient.RevocationSource.OCSP, Instant.now());
    }
}
