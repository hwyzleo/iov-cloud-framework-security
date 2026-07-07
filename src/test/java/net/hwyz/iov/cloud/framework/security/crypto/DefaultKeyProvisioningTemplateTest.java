package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.ProvisioningResult;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DefaultKeyProvisioningTemplateTest {

    private static final String PROVIDER = "Vault-Transit";

    private KmsClient kmsClient;
    private CryptoMetrics cryptoMetrics;
    private CryptoProperties properties;
    private DeviceResolver deviceResolver;
    private DefaultKeyProvisioningTemplate template;

    @BeforeEach
    void setUp() {
        kmsClient = mock(KmsClient.class);
        cryptoMetrics = mock(CryptoMetrics.class);
        properties = new CryptoProperties();
        properties.getProvisioning().setProvider(PROVIDER);
        deviceResolver = mock(DeviceResolver.class);
        template = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, deviceResolver);
    }

    private byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // ==================== deriveByVin — VEHICLE anchor（不解析设备） ====================

    @Test
    void deriveByVin_vehicleAnchor_noDeviceResolve() {
        String vin = "VIN12345";
        byte[] derived = {1, 2, 3, 4, 5, 6, 7, 8};
        when(kmsClient.hmac("v2c-comm-root", bytes(vin))).thenReturn(derived);

        ProvisioningResult result = template.deriveByVin(vin, BizType.V2C_COMM_ROOT);

        assertEquals("v2c-comm-root:vin:VIN12345", result.getKmsKeyRef());
        assertEquals("HMAC-SHA256", result.getAlgorithm());
        assertArrayEquals(Arrays.copyOf(derived, 4), result.getKcv());
        assertNull(result.getWrappedMaterial());
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
        verify(cryptoMetrics).recordProvisioningDerive(anyLong());
    }

    @Test
    void deriveByVin_vehicleAnchor_kmsFailure_failClosed() {
        when(kmsClient.hmac("v2c-comm-root", bytes("VIN123"))).thenThrow(new CryptoDependencyUnavailableException("down"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.deriveByVin("VIN123", BizType.V2C_COMM_ROOT));
        verify(cryptoMetrics).recordError();
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
    }

    @Test
    void deriveByVin_vehicleAnchor_resolverNull_works() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);
        when(kmsClient.hmac("v2c-comm-root", bytes("VIN123"))).thenReturn(new byte[]{1, 2, 3, 4});

        ProvisioningResult result = t.deriveByVin("VIN123", BizType.V2C_COMM_ROOT);
        assertNotNull(result);
        assertEquals("v2c-comm-root:vin:VIN123", result.getKmsKeyRef());
    }

    // ==================== deriveByVin — 通用校验 ====================

    @Test
    void deriveByVin_nullVin_throwsNpe() {
        assertThrows(NullPointerException.class, () -> template.deriveByVin(null, BizType.V2C_COMM_ROOT));
    }

    // ==================== deriveByUid — VEHICLE anchor fail-closed ====================

    @Test
    void deriveByUid_vehicleAnchor_throws() {
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE,
                assertThrows(CryptoException.class,
                        () -> template.deriveByUid("SN123", BizType.V2C_COMM_ROOT)).getReason());
        verify(kmsClient, never()).hmac(any(), any());
    }

    // ==================== wrapByVin（by-reference，收方恒为器件，始终解析设备） ====================

    @Test
    void wrapByVin_vehicleAnchor_success() {
        byte[] derived = {1, 2, 3, 4, 5, 6, 7, 8}, wrapped = {99, 88, 77};
        when(deviceResolver.resolveDeviceSn("VIN12345", BizType.V2C_COMM_ROOT)).thenReturn("SN12345");
        when(kmsClient.hmac("v2c-comm-root", bytes("VIN12345"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-SN12345", derived)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapByVin("VIN12345", BizType.V2C_COMM_ROOT);

        assertEquals("dev-SN12345", result.getKmsKeyRef());
        assertEquals("HMAC-SHA256+AES-256-GCM", result.getAlgorithm());
        assertArrayEquals(Arrays.copyOf(derived, 4), result.getKcv());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
        verify(deviceResolver).resolveDeviceSn("VIN12345", BizType.V2C_COMM_ROOT);
        verify(cryptoMetrics).recordProvisioningWrap(anyLong());
    }

    @Test
    void wrapByVin_deviceAnchor_success() {
        byte[] derived = {10, 20, 30, 40}, wrapped = {55, 66};
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.TBOX_DEVICE_ROOT)).thenReturn("SN123");
        when(kmsClient.hmac("tbox-dev-root", bytes("SN123"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-SN123", derived)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapByVin("VIN123", BizType.TBOX_DEVICE_ROOT);

        assertEquals("dev-SN123", result.getKmsKeyRef());
        assertArrayEquals(Arrays.copyOf(derived, 4), result.getKcv());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
    }

    @Test
    void wrapByVin_hmacFailure_failClosed() {
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.V2C_COMM_ROOT)).thenReturn("SN123");
        when(kmsClient.hmac("v2c-comm-root", bytes("VIN123"))).thenThrow(new CryptoDependencyUnavailableException("down"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapByVin("VIN123", BizType.V2C_COMM_ROOT));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void wrapByVin_encryptFailure_failClosed() {
        byte[] derived = {1, 2, 3, 4};
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.V2C_COMM_ROOT)).thenReturn("SN123");
        when(kmsClient.hmac("v2c-comm-root", bytes("VIN123"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-SN123", derived)).thenThrow(new CryptoDependencyUnavailableException("down"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapByVin("VIN123", BizType.V2C_COMM_ROOT));
        verify(cryptoMetrics).recordError();
    }

    // ==================== wrapByUid（by-reference，仅 anchor=DEVICE） ====================

    @Test
    void wrapByUid_deviceAnchor_success() {
        byte[] derived = {10, 20, 30, 40}, wrapped = {99, 88};
        when(kmsClient.hmac("tbox-dev-root", bytes("SN12345"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-SN12345", derived)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapByUid("SN12345", BizType.TBOX_DEVICE_ROOT);

        assertEquals("dev-SN12345", result.getKmsKeyRef());
        assertEquals("HMAC-SHA256+AES-256-GCM", result.getAlgorithm());
        assertArrayEquals(Arrays.copyOf(derived, 4), result.getKcv());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
    }

    @Test
    void wrapByUid_vehicleAnchor_throws() {
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE,
                assertThrows(CryptoException.class,
                        () -> template.wrapByUid("SN123", BizType.V2C_COMM_ROOT)).getReason());
        verify(kmsClient, never()).hmac(any(), any());
        verify(kmsClient, never()).encryptWith(any(), any());
    }

    @Test
    void wrapByUid_hmacFailure_failClosed() {
        when(kmsClient.hmac("tbox-dev-root", bytes("SN123"))).thenThrow(new CryptoDependencyUnavailableException("down"));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapByUid("SN123", BizType.TBOX_DEVICE_ROOT));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void wrapByUid_encryptFailure_failClosed() {
        byte[] derived = {1, 2, 3};
        when(kmsClient.hmac("tbox-dev-root", bytes("SN123"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-SN123", derived)).thenThrow(new CryptoDependencyUnavailableException("down"));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapByUid("SN123", BizType.TBOX_DEVICE_ROOT));
        verify(cryptoMetrics).recordError();
    }

    // ==================== wrapFor（跨设备封装，CR-004） ====================

    @Test
    void wrapFor_vehicleAnchor_success() {
        byte[] derived = {1, 2, 3, 4, 5, 6}, wrapped = {77, 88, 99};
        when(kmsClient.hmac("immo-group", bytes("VIN12345"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-KLD001", derived)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapFor(BizType.IMMO_GROUP_KEY, "VIN12345", "KLD001");

        assertEquals("dev-KLD001", result.getKmsKeyRef());
        assertEquals("HMAC-SHA256+AES-256-GCM", result.getAlgorithm());
        assertArrayEquals(Arrays.copyOf(derived, 4), result.getKcv());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
        verify(cryptoMetrics).recordProvisioningWrap(anyLong());
    }

    @Test
    void wrapFor_deviceAnchor_success() {
        byte[] derived = {10, 20, 30, 40}, wrapped = {44, 55};
        when(kmsClient.hmac("tbox-dev-root", bytes("SN123"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-KLD001", derived)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapFor(BizType.TBOX_DEVICE_ROOT, "SN123", "KLD001");

        assertEquals("dev-KLD001", result.getKmsKeyRef());
        assertArrayEquals(Arrays.copyOf(derived, 4), result.getKcv());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
    }

    @Test
    void wrapFor_hmacFailure_failClosed() {
        when(kmsClient.hmac("immo-group", bytes("VIN123"))).thenThrow(new CryptoDependencyUnavailableException("down"));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapFor(BizType.IMMO_GROUP_KEY, "VIN123", "KLD001"));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void wrapFor_encryptFailure_failClosed() {
        byte[] derived = {1, 2, 3};
        when(kmsClient.hmac("immo-group", bytes("VIN123"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-KLD001", derived)).thenThrow(new CryptoDependencyUnavailableException("down"));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapFor(BizType.IMMO_GROUP_KEY, "VIN123", "KLD001"));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void wrapFor_nullVinOrUid_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.wrapFor(BizType.IMMO_GROUP_KEY, null, "KLD001"));
    }

    @Test
    void wrapFor_nullRecipientUid_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.wrapFor(BizType.IMMO_GROUP_KEY, "VIN123", null));
    }

    @Test
    void wrapFor_idempotent_withWhitespace() {
        byte[] derived = {1, 2, 3}, wrapped = {99};
        when(kmsClient.hmac("immo-group", bytes("VIN123"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-KLD001", derived)).thenReturn(wrapped);

        ProvisioningResult padded = template.wrapFor(BizType.IMMO_GROUP_KEY, " VIN123 ", " KLD001 ");
        ProvisioningResult clean = template.wrapFor(BizType.IMMO_GROUP_KEY, "VIN123", "KLD001");

        assertEquals(padded.getKmsKeyRef(), clean.getKmsKeyRef());
    }

    // ==================== unwrapByVin ====================

    @Test
    void unwrapByVin_success() {
        byte[] wrapped = {5, 6, 7}, material = {42};
        when(deviceResolver.resolveDeviceSn("VIN12345", BizType.V2C_COMM_ROOT)).thenReturn("SN12345");
        when(kmsClient.decryptWith("dev-SN12345", wrapped)).thenReturn(material);

        assertArrayEquals(material, template.unwrapByVin("VIN12345", BizType.V2C_COMM_ROOT, wrapped));
        verify(cryptoMetrics).recordProvisioningUnwrap(anyLong());
    }

    @Test
    void unwrapByVin_kmsFailure_failClosed() {
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.V2C_COMM_ROOT)).thenReturn("SN123");
        when(kmsClient.decryptWith("dev-SN123", new byte[]{1})).thenThrow(new CryptoDependencyUnavailableException("down"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.unwrapByVin("VIN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    // ==================== unwrapByUid ====================

    @Test
    void unwrapByUid_success() {
        byte[] wrapped = {5, 6, 7}, material = {42};
        when(kmsClient.decryptWith("dev-SN12345", wrapped)).thenReturn(material);

        assertArrayEquals(material, template.unwrapByUid("SN12345", BizType.V2C_COMM_ROOT, wrapped));
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
    }

    @Test
    void unwrapByUid_kmsFailure_failClosed() {
        when(kmsClient.decryptWith("dev-SN123", new byte[]{1})).thenThrow(new CryptoDependencyUnavailableException("down"));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.unwrapByUid("SN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    // ==================== 封装/解封等价性（by-reference） ====================

    @Test
    void wrapAndUnwrap_byVinAndByUid_deviceAnchor_sameDeviceSn_useSameDevKey() {
        byte[] derived = {10, 20, 30}, wrapped = {99, 88};
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.TBOX_DEVICE_ROOT)).thenReturn("SN123");
        when(kmsClient.hmac("tbox-dev-root", bytes("SN123"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-SN123", derived)).thenReturn(wrapped);
        when(kmsClient.decryptWith("dev-SN123", wrapped)).thenReturn(derived);

        ProvisioningResult wrapByVin = template.wrapByVin("VIN123", BizType.TBOX_DEVICE_ROOT);
        ProvisioningResult wrapByUid = template.wrapByUid("SN123", BizType.TBOX_DEVICE_ROOT);

        assertEquals(wrapByVin.getKmsKeyRef(), wrapByUid.getKmsKeyRef());
        assertArrayEquals(derived, template.unwrapByVin("VIN123", BizType.TBOX_DEVICE_ROOT, wrapped));
        assertArrayEquals(derived, template.unwrapByUid("SN123", BizType.TBOX_DEVICE_ROOT, wrapped));
    }

    // ==================== 规范化 / 幂等性 ====================

    @Test
    void deriveByVin_vehicleAnchor_idempotent_differentCasing() {
        byte[] derived = {1, 2, 3, 4};
        when(kmsClient.hmac("v2c-comm-root", bytes("VIN12345"))).thenReturn(derived);

        ProvisioningResult lower = template.deriveByVin("vin12345", BizType.V2C_COMM_ROOT);
        ProvisioningResult upper = template.deriveByVin("VIN12345", BizType.V2C_COMM_ROOT);

        assertEquals(lower.getKmsKeyRef(), upper.getKmsKeyRef());
        assertArrayEquals(lower.getKcv(), upper.getKcv());
    }

    @Test
    void wrapByUid_idempotent_withWhitespace() {
        byte[] derived = {1}, wrapped = {99};
        when(kmsClient.hmac("tbox-dev-root", bytes("SN123"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-SN123", derived)).thenReturn(wrapped);

        ProvisioningResult padded = template.wrapByUid(" SN123 ", BizType.TBOX_DEVICE_ROOT);
        ProvisioningResult clean = template.wrapByUid("SN123", BizType.TBOX_DEVICE_ROOT);

        assertEquals(padded.getKmsKeyRef(), clean.getKmsKeyRef());
    }

    // ==================== *ByVin 无 DeviceResolver 时 ====================

    @Test
    void byVinMethods_vehicleAnchor_deriveWorks_wrapThrows() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);
        when(kmsClient.hmac("v2c-comm-root", bytes("VIN123"))).thenReturn(new byte[]{1, 2, 3, 4});

        // VEHICLE deriveByVin 不需要 DeviceResolver
        assertNotNull(t.deriveByVin("VIN123", BizType.V2C_COMM_ROOT));

        // wrap/unwrap 收方恒为器件，*ByVin 始终需要 DeviceResolver
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.wrapByVin("VIN123", BizType.V2C_COMM_ROOT));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.unwrapByVin("VIN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
    }

    // ==================== *ByUid 不依赖 DeviceResolver ====================

    @Test
    void byUidMethods_resolverNull_wrapUnwrapWork() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);
        byte[] derived = {1, 2, 3}, wrapped = {99};
        when(kmsClient.hmac("tbox-dev-root", bytes("SN123"))).thenReturn(derived);
        when(kmsClient.encryptWith("dev-SN123", derived)).thenReturn(wrapped);
        when(kmsClient.decryptWith("dev-SN123", wrapped)).thenReturn(derived);

        assertNotNull(t.wrapByUid("SN123", BizType.TBOX_DEVICE_ROOT));
        assertArrayEquals(derived, t.unwrapByUid("SN123", BizType.TBOX_DEVICE_ROOT, wrapped));
    }
}
