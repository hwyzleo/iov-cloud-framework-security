package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.KeyMaterialModelMismatchException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.EvidenceSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * DefaultKeyProvisioningTemplate 根派生门面测试（FW-SEC-DSN-CR-013 §4.4/§7.2/§7.3）。
 * <p>
 * 覆盖：deriveAndWrap 编排（bizType→受治理根、锚层级校验、证书证据解析、purpose/派生版本/operationId）、
 * 材料模型与锚类型 fail-closed、legacy 门面 fail-closed 及受控 legacy 解封开关。
 */
class DefaultKeyProvisioningTemplateTest {

    private static final String VIN = "LSVAA4187N2123456";

    private KmsClient kmsClient;
    private CryptoMetrics cryptoMetrics;
    private CryptoProperties properties;
    private DeviceResolver deviceResolver;
    private CertResolver certResolver;
    private DefaultKeyProvisioningTemplate template;

    private byte[] leafCertDer;

    @BeforeEach
    void setUp() throws Exception {
        kmsClient = mock(KmsClient.class);
        cryptoMetrics = mock(CryptoMetrics.class);
        properties = new CryptoProperties();
        deviceResolver = mock(DeviceResolver.class);
        certResolver = mock(CertResolver.class);
        leafCertDer = TestPkiMaterial.generate().leafCert().getEncoded();
        when(certResolver.resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class)))
                .thenReturn(CertificateEvidenceValidator.fromCertificateDer(
                        leafCertDer, EvidenceSource.PROVIDER_QUERY));
        template = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties,
                deviceResolver, certResolver, null);
    }

    private DefaultKeyProvisioningTemplate templateWith(boolean legacyFacade) {
        properties.getProvisioning().setLegacyFacadeEnabled(legacyFacade);
        return new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties,
                deviceResolver, certResolver, null);
    }

    // ==================== deriveAndWrap 成功编排 ====================

    @Test
    void deriveAndWrap_v2cUplink_mapsGovernedRootAndRecipient() {
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        DerivedWrappedKey providerResult = new DerivedWrappedKey(
                "logical-v2c-uplink", "openbao-derived://transit/v2c-comm-root/v1/" + anchor.digest() + "/UPLINK_AEAD",
                3L, "v1", WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                new byte[]{9, 8, 7}, new byte[]{4, 5, 6}, new byte[]{1, 2, 3}, "op-1");
        when(kmsClient.deriveAndWrap(any(), any(), any(), any())).thenReturn(providerResult);

        DerivedWrappedKey result = template.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor,
                KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate("cert-001"),
                DerivationContext.v1(), "op-1", "idem-1",
                "req-1", "V2C_COMM");

        assertArrayEquals(new byte[]{9, 8, 7}, result.envelopeBytes());
        assertArrayEquals(new byte[]{1, 2, 3}, result.kcv());
        assertEquals("v1", result.derivationVersion());
        assertEquals(3, result.rootKeyVersion());
        verify(kmsClient).deriveAndWrap(
                argThat(ref -> "V2C_COMM_ROOT".equals(ref.bizType())
                        && "openbao-transit://transit/keys/v2c-comm-root".equals(ref.rootKeyRef())),
                argThat(in -> in.purpose() == KeyPurpose.UPLINK_AEAD
                        && anchor.equals(in.anchor()) && "v1".equals(in.derivationVersion())),
                argThat(r -> r.mode() == WrapMode.DEVICE_CERT_PUBLIC_KEY
                        && "cert-001".equals(r.certSerial())
                        && r.certificateDer() != null && r.certificateDer().length > 0
                        && r.certificateSha256Fingerprint() != null
                        && r.spki() != null && r.spki().length > 0),
                argThat(op -> "op-1".equals(op.operationId()) && "idem-1".equals(op.idempotencyKey())));
        verify(certResolver).resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class));
        verify(cryptoMetrics).recordProvisioningWrap(anyLong());
    }

    @Test
    void deriveAndWrap_uplinkAndDownlink_purposeDomainSeparated() {
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        when(kmsClient.deriveAndWrap(any(), any(), any(), any())).thenReturn(new DerivedWrappedKey(
                "l", "ref", 1L, "v1", WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                new byte[]{1}, new byte[]{3}, new byte[]{2}, "op"));

        template.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor, KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(), "op-u", "idem-u",
                "req-u", "V2C_COMM");
        template.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor, KeyPurpose.DOWNLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(), "op-d", "idem-d",
                "req-d", "V2C_COMM");

        verify(kmsClient).deriveAndWrap(any(), argThat(in -> in.purpose() == KeyPurpose.UPLINK_AEAD),
                any(), any());
        verify(kmsClient).deriveAndWrap(any(), argThat(in -> in.purpose() == KeyPurpose.DOWNLINK_AEAD),
                any(), any());
    }

    @Test
    void deriveAndWrap_kmsFailure_failClosed() {
        when(kmsClient.deriveAndWrap(any(), any(), any(), any()))
                .thenThrow(new CryptoDependencyUnavailableException("derived provider down"));

        assertThrows(CryptoDependencyUnavailableException.class, () -> template.deriveAndWrap(
                BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(), "op-1", "idem-1",
                "req-1", "V2C_COMM"));
        verify(cryptoMetrics).recordError();
    }

    // ==================== 材料模型 / 锚类型 fail-closed ====================

    @Test
    void deriveAndWrap_nonDerivedRootModel_failClosed() {
        assertThrows(KeyMaterialModelMismatchException.class, () -> template.deriveAndWrap(
                BizType.IDK_KTS_SIGNING, KeyAnchor.uid("SN123"), KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(), "op-1", "idem-1",
                "req-1", "V2C_COMM"));
        verify(kmsClient, never()).deriveAndWrap(any(), any(), any(), any());
    }

    @Test
    void deriveAndWrap_vehicleAnchorRequiresVinAnchor() {
        CryptoException ex = assertThrows(CryptoException.class, () -> template.deriveAndWrap(
                BizType.V2C_COMM_ROOT, KeyAnchor.uid("SN123"), KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(), "op-1", "idem-1",
                "req-1", "V2C_COMM"));
        assertEquals(CryptoException.Reason.INVALID_KEY_ANCHOR, ex.getReason());
        verify(kmsClient, never()).deriveAndWrap(any(), any(), any(), any());
    }

    @Test
    void deriveAndWrap_deviceAnchorRequiresUidAnchor() {
        CryptoException ex = assertThrows(CryptoException.class, () -> template.deriveAndWrap(
                BizType.TBOX_DEVICE_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(), "op-1", "idem-1",
                "req-1", "V2C_COMM"));
        assertEquals(CryptoException.Reason.INVALID_KEY_ANCHOR, ex.getReason());
    }

    @Test
    void deriveAndWrap_unsupportedRecipient_failClosed() {
        CryptoException ex = assertThrows(CryptoException.class, () -> template.deriveAndWrap(
                BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD,
                new RecipientRef.RuntimeIdentity("runtime"), DerivationContext.v1(), "op-1", "idem-1",
                "req-1", "V2C_COMM"));
        assertEquals(CryptoException.Reason.UNSUPPORTED_RECIPIENT, ex.getReason());
        verify(kmsClient, never()).deriveAndWrap(any(), any(), any(), any());
    }

    @Test
    void deriveAndWrap_blankOperationIdOrIdempotencyKey_failClosed() {
        assertThrows(IllegalArgumentException.class, () -> template.deriveAndWrap(
                BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(), " ", "idem-1",
                "req-1", "V2C_COMM"));
        assertThrows(NullPointerException.class, () -> template.deriveAndWrap(
                BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.v1(), "op-1", null,
                "req-1", "V2C_COMM"));
    }

    // ==================== legacy 门面 fail-closed ====================

    @Test
    void legacyDeriveAndWrapFacades_areFailClosed() {
        assertEquals(CryptoException.Reason.LEGACY_FACADE_UNSUPPORTED,
                assertThrows(CryptoException.class, () -> template.deriveByVin(VIN, BizType.V2C_COMM_ROOT)).getReason());
        assertEquals(CryptoException.Reason.LEGACY_FACADE_UNSUPPORTED,
                assertThrows(CryptoException.class, () -> template.deriveByUid("SN123", BizType.TBOX_DEVICE_ROOT)).getReason());
        assertEquals(CryptoException.Reason.LEGACY_FACADE_UNSUPPORTED,
                assertThrows(CryptoException.class, () -> template.wrapByVin(VIN, BizType.V2C_COMM_ROOT)).getReason());
        assertEquals(CryptoException.Reason.LEGACY_FACADE_UNSUPPORTED,
                assertThrows(CryptoException.class, () -> template.wrapByUid("SN123", BizType.TBOX_DEVICE_ROOT)).getReason());
        assertEquals(CryptoException.Reason.LEGACY_FACADE_UNSUPPORTED,
                assertThrows(CryptoException.class, () -> template.wrapFor(BizType.IMMO_GROUP_KEY, VIN, "KLD001")).getReason());
        verify(kmsClient, never()).hmac(any(), any());
        verify(kmsClient, never()).encryptWith(any(), any());
    }

    @Test
    void unwrapByVinByUid_defaultDisabled_failClosed() {
        assertEquals(CryptoException.Reason.LEGACY_FACADE_UNSUPPORTED,
                assertThrows(CryptoException.class,
                        () -> template.unwrapByVin(VIN, BizType.V2C_COMM_ROOT, new byte[]{1})).getReason());
        assertEquals(CryptoException.Reason.LEGACY_FACADE_UNSUPPORTED,
                assertThrows(CryptoException.class,
                        () -> template.unwrapByUid("SN123", BizType.TBOX_DEVICE_ROOT, new byte[]{1})).getReason());
        verify(kmsClient, never()).decryptWith(any(), any());
    }

    @Test
    void unwrapByUid_enabled_preservesLegacySymmetricKekPath() {
        DefaultKeyProvisioningTemplate legacy = templateWith(true);
        when(kmsClient.decryptWith("dev-SN123", new byte[]{9})).thenReturn(new byte[]{42});

        assertArrayEquals(new byte[]{42}, legacy.unwrapByUid(" SN123 ", BizType.TBOX_DEVICE_ROOT, new byte[]{9}));
        verify(cryptoMetrics).recordProvisioningUnwrap(anyLong());
    }

    @Test
    void unwrapByVin_enabled_normalizesVinAndResolvesDevice() {
        DefaultKeyProvisioningTemplate legacy = templateWith(true);
        when(deviceResolver.resolveDeviceSn(VIN, BizType.V2C_COMM_ROOT)).thenReturn("SN1");
        when(kmsClient.decryptWith("dev-SN1", new byte[]{7})).thenReturn(new byte[]{1});

        assertArrayEquals(new byte[]{1}, legacy.unwrapByVin("  " + VIN.toLowerCase() + "  ",
                BizType.V2C_COMM_ROOT, new byte[]{7}));
        verify(deviceResolver).resolveDeviceSn(VIN, BizType.V2C_COMM_ROOT);
    }
}
