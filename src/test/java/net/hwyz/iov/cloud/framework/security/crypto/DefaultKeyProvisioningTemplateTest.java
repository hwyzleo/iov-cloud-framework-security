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

    // ==================== wrapByVin（收方恒为器件，始终解析设备） ====================

    @Test
    void wrapByVin_success() {
        byte[] material = {10, 20, 30, 40}, wrapped = {99, 88, 77};
        when(deviceResolver.resolveDeviceSn("VIN12345", BizType.V2C_COMM_ROOT)).thenReturn("SN12345");
        when(kmsClient.encryptWith("dev-SN12345", material)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapByVin("VIN12345", BizType.V2C_COMM_ROOT, material);

        assertEquals("dev-SN12345", result.getKmsKeyRef());
        assertEquals("AES-256-GCM", result.getAlgorithm());
        assertArrayEquals(Arrays.copyOf(material, 4), result.getKcv());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
        verify(deviceResolver).resolveDeviceSn("VIN12345", BizType.V2C_COMM_ROOT);
        verify(cryptoMetrics).recordProvisioningWrap(anyLong());
    }

    @Test
    void wrapByVin_kmsFailure_failClosed() {
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.V2C_COMM_ROOT)).thenReturn("SN123");
        when(kmsClient.encryptWith("dev-SN123", new byte[]{1})).thenThrow(new CryptoDependencyUnavailableException("down"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapByVin("VIN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    // ==================== wrapByUid ====================

    @Test
    void wrapByUid_success() {
        byte[] material = {10, 20, 30}, wrapped = {99, 88};
        when(kmsClient.encryptWith("dev-SN12345", material)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapByUid("SN12345", BizType.V2C_COMM_ROOT, material);

        assertEquals("dev-SN12345", result.getKmsKeyRef());
        assertEquals("AES-256-GCM", result.getAlgorithm());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
    }

    @Test
    void wrapByUid_kmsFailure_failClosed() {
        when(kmsClient.encryptWith("dev-SN123", new byte[]{1})).thenThrow(new CryptoDependencyUnavailableException("down"));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapByUid("SN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
        verify(cryptoMetrics).recordError();
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

    // ==================== 封装/解封等价性 ====================

    @Test
    void wrapAndUnwrap_byVinAndByUid_sameDeviceSn_useSameDevKey() {
        byte[] material = {10, 20, 30}, wrapped = {99, 88};
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.V2C_COMM_ROOT)).thenReturn("SN123");
        when(kmsClient.encryptWith("dev-SN123", material)).thenReturn(wrapped);
        when(kmsClient.decryptWith("dev-SN123", wrapped)).thenReturn(material);

        ProvisioningResult wrapByVin = template.wrapByVin("VIN123", BizType.V2C_COMM_ROOT, material);
        ProvisioningResult wrapByUid = template.wrapByUid("SN123", BizType.V2C_COMM_ROOT, material);

        assertEquals(wrapByVin.getKmsKeyRef(), wrapByUid.getKmsKeyRef());

        assertArrayEquals(material, template.unwrapByVin("VIN123", BizType.V2C_COMM_ROOT, wrapped));
        assertArrayEquals(material, template.unwrapByUid("SN123", BizType.V2C_COMM_ROOT, wrapped));
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
        byte[] material = {1}, wrapped = {99};
        when(kmsClient.encryptWith("dev-SN123", material)).thenReturn(wrapped);

        ProvisioningResult padded = template.wrapByUid(" SN123 ", BizType.V2C_COMM_ROOT, material);
        ProvisioningResult clean = template.wrapByUid("SN123", BizType.V2C_COMM_ROOT, material);

        assertEquals(padded.getKmsKeyRef(), clean.getKmsKeyRef());
    }

    // ==================== *ByVin 无 DeviceResolver 时 ====================

    @Test
    void byVinMethods_vehicleAnchor_deriveWorks_wrapUnwrapThrow() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);
        when(kmsClient.hmac("v2c-comm-root", bytes("VIN123"))).thenReturn(new byte[]{1, 2, 3, 4});

        // VEHICLE deriveByVin 不需要 DeviceResolver
        assertNotNull(t.deriveByVin("VIN123", BizType.V2C_COMM_ROOT));

        // wrap/unwrap 收方恒为器件，*ByVin 始终需要 DeviceResolver
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.wrapByVin("VIN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.unwrapByVin("VIN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
    }

    // ==================== *ByUid 不依赖 DeviceResolver ====================

    @Test
    void byUidMethods_resolverNull_wrapUnwrapWork() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);
        when(kmsClient.encryptWith("dev-SN123", new byte[]{1})).thenReturn(new byte[]{99});
        when(kmsClient.decryptWith("dev-SN123", new byte[]{99})).thenReturn(new byte[]{1});

        assertNotNull(t.wrapByUid("SN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
        assertArrayEquals(new byte[]{1}, t.unwrapByUid("SN123", BizType.V2C_COMM_ROOT, new byte[]{99}));
    }
}
