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

    // ==================== deriveByVin — anchor=VEHICLE（不解析设备） ====================

    @Test
    void deriveByVin_vehicleAnchor_noDeviceResolve() {
        String vin = "VIN12345";
        byte[] derived = {1, 2, 3, 4, 5, 6, 7, 8};
        when(kmsClient.hmac("secoc-master", bytes(vin))).thenReturn(derived);

        ProvisioningResult result = template.deriveByVin(vin, BizType.SECOC_GROUP);

        assertEquals("secoc-master:vin:VIN12345", result.getKmsKeyRef());
        assertEquals("HMAC-SHA256", result.getAlgorithm());
        assertArrayEquals(Arrays.copyOf(derived, 4), result.getKcv());
        assertNull(result.getWrappedMaterial());
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
        verify(cryptoMetrics).recordProvisioningDerive(anyLong());
    }

    @Test
    void deriveByVin_vehicleAnchor_kmsFailure_failClosed() {
        when(kmsClient.hmac("secoc-master", bytes("VIN123"))).thenThrow(new CryptoDependencyUnavailableException("down"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.deriveByVin("VIN123", BizType.SECOC_GROUP));
        verify(cryptoMetrics).recordError();
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
    }

    @Test
    void deriveByVin_vehicleAnchor_resolverNull_works() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);
        when(kmsClient.hmac("secoc-master", bytes("VIN123"))).thenReturn(new byte[]{1, 2, 3, 4});

        ProvisioningResult result = t.deriveByVin("VIN123", BizType.SECOC_GROUP);
        assertNotNull(result);
        assertEquals("secoc-master:vin:VIN123", result.getKmsKeyRef());
    }

    // ==================== deriveByVin — anchor=DEVICE（解析设备） ====================

    @Test
    void deriveByVin_deviceAnchor_resolvesDevice() {
        String vin = "VIN12345", deviceSn = "SN12345";
        byte[] derived = {1, 2, 3, 4, 5, 6};
        when(deviceResolver.resolveDeviceSn(vin, BizType.DEVICE_ROOT)).thenReturn(deviceSn);
        when(kmsClient.hmac("dev-root-master", bytes(deviceSn))).thenReturn(derived);

        ProvisioningResult result = template.deriveByVin(vin, BizType.DEVICE_ROOT);

        assertEquals("dev-root-master:sn:SN12345", result.getKmsKeyRef());
        assertEquals("HMAC-SHA256", result.getAlgorithm());
        assertArrayEquals(Arrays.copyOf(derived, 4), result.getKcv());
        assertNull(result.getWrappedMaterial());
        verify(deviceResolver).resolveDeviceSn(vin, BizType.DEVICE_ROOT);
    }

    @Test
    void deriveByVin_deviceAnchor_kmsFailure_failClosed() {
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.DEVICE_ROOT)).thenReturn("SN123");
        when(kmsClient.hmac("dev-root-master", bytes("SN123"))).thenThrow(new CryptoDependencyUnavailableException("down"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.deriveByVin("VIN123", BizType.DEVICE_ROOT));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void deriveByVin_deviceAnchor_resolverNull_throws() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.deriveByVin("VIN123", BizType.DEVICE_ROOT));
    }

    // ==================== deriveByVin — 通用校验 ====================

    @Test
    void deriveByVin_dataBizType_throws() {
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE,
                assertThrows(CryptoException.class,
                        () -> template.deriveByVin("VIN123", BizType.REMOTE_CONTROL)).getReason());
        verify(kmsClient, never()).hmac(any(), any());
    }

    @Test
    void deriveByVin_dualUseBizType_works() {
        String vin = "VIN12345", deviceSn = "SN12345";
        when(deviceResolver.resolveDeviceSn(vin, BizType.TELEMETRY)).thenReturn(deviceSn);
        when(kmsClient.hmac("telemetry-root", bytes(deviceSn))).thenReturn(new byte[]{1, 2, 3, 4});

        ProvisioningResult result = template.deriveByVin(vin, BizType.TELEMETRY);
        assertEquals("telemetry-root:sn:SN12345", result.getKmsKeyRef());
    }

    @Test
    void deriveByVin_nullVin_throwsNpe() {
        assertThrows(NullPointerException.class, () -> template.deriveByVin(null, BizType.SECOC_GROUP));
    }

    // ==================== deriveByUid — anchor=DEVICE ====================

    @Test
    void deriveByUid_deviceAnchor_success() {
        byte[] derived = {1, 2, 3, 4, 5, 6};
        when(kmsClient.hmac("dev-root-master", bytes("SN12345"))).thenReturn(derived);

        ProvisioningResult result = template.deriveByUid("SN12345", BizType.DEVICE_ROOT);

        assertEquals("dev-root-master:sn:SN12345", result.getKmsKeyRef());
        assertEquals("HMAC-SHA256", result.getAlgorithm());
        assertArrayEquals(Arrays.copyOf(derived, 4), result.getKcv());
        assertNull(result.getWrappedMaterial());
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
    }

    @Test
    void deriveByUid_deviceAnchor_kmsFailure_failClosed() {
        when(kmsClient.hmac("dev-root-master", bytes("SN123"))).thenThrow(new CryptoDependencyUnavailableException("down"));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.deriveByUid("SN123", BizType.DEVICE_ROOT));
        verify(cryptoMetrics).recordError();
    }

    // ==================== deriveByUid — anchor=VEHICLE fail-closed ====================

    @Test
    void deriveByUid_vehicleAnchor_throws() {
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE,
                assertThrows(CryptoException.class,
                        () -> template.deriveByUid("SN123", BizType.SECOC_GROUP)).getReason());
        verify(kmsClient, never()).hmac(any(), any());
    }

    @Test
    void deriveByUid_dataBizType_throws() {
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE,
                assertThrows(CryptoException.class,
                        () -> template.deriveByUid("SN123", BizType.REMOTE_CONTROL)).getReason());
    }

    // ==================== 派生等价性（DEVICE anchor，ByVin 与 ByUid 同值） ====================

    @Test
    void deriveByVinAndByUid_deviceAnchor_sameDeviceSn_produceSameSecret() {
        String vin = "VIN12345", deviceSn = "SN12345";
        byte[] derived = {10, 20, 30, 40, 50, 60};
        when(deviceResolver.resolveDeviceSn(vin, BizType.DEVICE_ROOT)).thenReturn(deviceSn);
        when(kmsClient.hmac("dev-root-master", bytes(deviceSn))).thenReturn(derived);

        ProvisioningResult byVin = template.deriveByVin(vin, BizType.DEVICE_ROOT);
        ProvisioningResult byUid = template.deriveByUid(deviceSn, BizType.DEVICE_ROOT);

        assertEquals(byVin.getKmsKeyRef(), byUid.getKmsKeyRef());
        assertArrayEquals(byVin.getKcv(), byUid.getKcv());
        verify(kmsClient, times(2)).hmac("dev-root-master", bytes(deviceSn));
    }

    @Test
    void deriveByVinAndByUid_differentDeviceSn_produceDifferentResults() {
        when(deviceResolver.resolveDeviceSn("VIN111", BizType.DEVICE_ROOT)).thenReturn("SN111");
        when(kmsClient.hmac("dev-root-master", bytes("SN111"))).thenReturn(new byte[]{1, 2, 3, 4});
        when(kmsClient.hmac("dev-root-master", bytes("SN222"))).thenReturn(new byte[]{5, 6, 7, 8});

        ProvisioningResult r1 = template.deriveByVin("VIN111", BizType.DEVICE_ROOT);
        ProvisioningResult r2 = template.deriveByUid("SN222", BizType.DEVICE_ROOT);

        assertNotEquals(r1.getKmsKeyRef(), r2.getKmsKeyRef());
    }

    // ==================== wrapByVin（收方恒为器件，始终解析设备） ====================

    @Test
    void wrapByVin_success() {
        byte[] material = {10, 20, 30, 40}, wrapped = {99, 88, 77};
        when(deviceResolver.resolveDeviceSn("VIN12345", BizType.DEVICE_ROOT)).thenReturn("SN12345");
        when(kmsClient.encryptWith("dev-SN12345", material)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapByVin("VIN12345", BizType.DEVICE_ROOT, material);

        assertEquals("dev-SN12345", result.getKmsKeyRef());
        assertEquals("AES-256-GCM", result.getAlgorithm());
        assertArrayEquals(Arrays.copyOf(material, 4), result.getKcv());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
        verify(cryptoMetrics).recordProvisioningWrap(anyLong());
    }

    @Test
    void wrapByVin_vehicleAnchor_alsoResolvesDevice() {
        byte[] material = {10, 20, 30}, wrapped = {99, 88};
        when(deviceResolver.resolveDeviceSn("VIN12345", BizType.SECOC_GROUP)).thenReturn("SN12345");
        when(kmsClient.encryptWith("dev-SN12345", material)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapByVin("VIN12345", BizType.SECOC_GROUP, material);

        assertEquals("dev-SN12345", result.getKmsKeyRef());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
        verify(deviceResolver).resolveDeviceSn("VIN12345", BizType.SECOC_GROUP);
    }

    @Test
    void wrapByVin_dataBizType_throws() {
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE,
                assertThrows(CryptoException.class,
                        () -> template.wrapByVin("VIN123", BizType.REMOTE_CONTROL, new byte[]{1})).getReason());
    }

    @Test
    void wrapByVin_kmsFailure_failClosed() {
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.DEVICE_ROOT)).thenReturn("SN123");
        when(kmsClient.encryptWith("dev-SN123", new byte[]{1})).thenThrow(new CryptoDependencyUnavailableException("down"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapByVin("VIN123", BizType.DEVICE_ROOT, new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    // ==================== wrapByUid ====================

    @Test
    void wrapByUid_success() {
        byte[] material = {10, 20, 30}, wrapped = {99, 88};
        when(kmsClient.encryptWith("dev-SN12345", material)).thenReturn(wrapped);

        ProvisioningResult result = template.wrapByUid("SN12345", BizType.DEVICE_ROOT, material);

        assertEquals("dev-SN12345", result.getKmsKeyRef());
        assertEquals("AES-256-GCM", result.getAlgorithm());
        assertArrayEquals(wrapped, result.getWrappedMaterial());
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
    }

    @Test
    void wrapByUid_kmsFailure_failClosed() {
        when(kmsClient.encryptWith("dev-SN123", new byte[]{1})).thenThrow(new CryptoDependencyUnavailableException("down"));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.wrapByUid("SN123", BizType.DEVICE_ROOT, new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    // ==================== unwrapByVin ====================

    @Test
    void unwrapByVin_success() {
        byte[] wrapped = {5, 6, 7}, material = {42};
        when(deviceResolver.resolveDeviceSn("VIN12345", BizType.DEVICE_ROOT)).thenReturn("SN12345");
        when(kmsClient.decryptWith("dev-SN12345", wrapped)).thenReturn(material);

        assertArrayEquals(material, template.unwrapByVin("VIN12345", BizType.DEVICE_ROOT, wrapped));
        verify(cryptoMetrics).recordProvisioningUnwrap(anyLong());
    }

    @Test
    void unwrapByVin_dataBizType_throws() {
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE,
                assertThrows(CryptoException.class,
                        () -> template.unwrapByVin("VIN123", BizType.REMOTE_CONTROL, new byte[]{1})).getReason());
    }

    @Test
    void unwrapByVin_kmsFailure_failClosed() {
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.DEVICE_ROOT)).thenReturn("SN123");
        when(kmsClient.decryptWith("dev-SN123", new byte[]{1})).thenThrow(new CryptoDependencyUnavailableException("down"));

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.unwrapByVin("VIN123", BizType.DEVICE_ROOT, new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    // ==================== unwrapByUid ====================

    @Test
    void unwrapByUid_success() {
        byte[] wrapped = {5, 6, 7}, material = {42};
        when(kmsClient.decryptWith("dev-SN12345", wrapped)).thenReturn(material);

        assertArrayEquals(material, template.unwrapByUid("SN12345", BizType.DEVICE_ROOT, wrapped));
        verify(deviceResolver, never()).resolveDeviceSn(any(), any());
    }

    @Test
    void unwrapByUid_dataBizType_throws() {
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE,
                assertThrows(CryptoException.class,
                        () -> template.unwrapByUid("SN123", BizType.REMOTE_CONTROL, new byte[]{1})).getReason());
    }

    @Test
    void unwrapByUid_kmsFailure_failClosed() {
        when(kmsClient.decryptWith("dev-SN123", new byte[]{1})).thenThrow(new CryptoDependencyUnavailableException("down"));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> template.unwrapByUid("SN123", BizType.DEVICE_ROOT, new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    // ==================== 封装/解封等价性 ====================

    @Test
    void wrapAndUnwrap_byVinAndByUid_sameDeviceSn_useSameDevKey() {
        byte[] material = {10, 20, 30}, wrapped = {99, 88};
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.DEVICE_ROOT)).thenReturn("SN123");
        when(kmsClient.encryptWith("dev-SN123", material)).thenReturn(wrapped);
        when(kmsClient.decryptWith("dev-SN123", wrapped)).thenReturn(material);

        ProvisioningResult wrapByVin = template.wrapByVin("VIN123", BizType.DEVICE_ROOT, material);
        ProvisioningResult wrapByUid = template.wrapByUid("SN123", BizType.DEVICE_ROOT, material);

        assertEquals(wrapByVin.getKmsKeyRef(), wrapByUid.getKmsKeyRef());

        assertArrayEquals(material, template.unwrapByVin("VIN123", BizType.DEVICE_ROOT, wrapped));
        assertArrayEquals(material, template.unwrapByUid("SN123", BizType.DEVICE_ROOT, wrapped));
    }

    // ==================== 规范化 / 幂等性 ====================

    @Test
    void deriveByVin_vehicleAnchor_idempotent_differentCasing() {
        byte[] derived = {1, 2, 3, 4};
        when(kmsClient.hmac("secoc-master", bytes("VIN12345"))).thenReturn(derived);

        ProvisioningResult lower = template.deriveByVin("vin12345", BizType.SECOC_GROUP);
        ProvisioningResult upper = template.deriveByVin("VIN12345", BizType.SECOC_GROUP);

        assertEquals(lower.getKmsKeyRef(), upper.getKmsKeyRef());
        assertArrayEquals(lower.getKcv(), upper.getKcv());
    }

    @Test
    void deriveByUid_idempotent_withWhitespace() {
        byte[] derived = {1, 2, 3, 4};
        when(kmsClient.hmac("dev-root-master", bytes("SN123"))).thenReturn(derived);

        ProvisioningResult padded = template.deriveByUid(" SN123 ", BizType.DEVICE_ROOT);
        ProvisioningResult clean = template.deriveByUid("SN123", BizType.DEVICE_ROOT);

        assertEquals(padded.getKmsKeyRef(), clean.getKmsKeyRef());
        assertArrayEquals(padded.getKcv(), clean.getKcv());
    }

    @Test
    void wrapByUid_idempotent_withWhitespace() {
        byte[] material = {1}, wrapped = {99};
        when(kmsClient.encryptWith("dev-SN123", material)).thenReturn(wrapped);

        ProvisioningResult padded = template.wrapByUid(" SN123 ", BizType.DEVICE_ROOT, material);
        ProvisioningResult clean = template.wrapByUid("SN123", BizType.DEVICE_ROOT, material);

        assertEquals(padded.getKmsKeyRef(), clean.getKmsKeyRef());
    }

    // ==================== *ByVin 无 DeviceResolver 时 ====================

    @Test
    void byVinMethods_vehicleAnchor_deriveWorks_wrapUnwrapThrow() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);
        when(kmsClient.hmac("secoc-master", bytes("VIN123"))).thenReturn(new byte[]{1, 2, 3, 4});

        // VEHICLE deriveByVin 不需要 DeviceResolver
        assertNotNull(t.deriveByVin("VIN123", BizType.SECOC_GROUP));

        // wrap/unwrap 收方恒为器件，*ByVin 始终需要 DeviceResolver
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.wrapByVin("VIN123", BizType.SECOC_GROUP, new byte[]{1}));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.unwrapByVin("VIN123", BizType.SECOC_GROUP, new byte[]{1}));
    }

    @Test
    void byVinMethods_deviceAnchor_allThrow() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);

        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.deriveByVin("VIN123", BizType.DEVICE_ROOT));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.wrapByVin("VIN123", BizType.DEVICE_ROOT, new byte[]{1}));
        assertThrows(CryptoDependencyUnavailableException.class,
                () -> t.unwrapByVin("VIN123", BizType.DEVICE_ROOT, new byte[]{1}));
    }

    // ==================== *ByUid 不依赖 DeviceResolver ====================

    @Test
    void byUidMethods_resolverNull_deviceAnchor_works() {
        DefaultKeyProvisioningTemplate t = new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties, null);
        when(kmsClient.hmac("dev-root-master", bytes("SN123"))).thenReturn(new byte[]{1, 2, 3, 4});
        when(kmsClient.encryptWith("dev-SN123", new byte[]{1})).thenReturn(new byte[]{99});
        when(kmsClient.decryptWith("dev-SN123", new byte[]{99})).thenReturn(new byte[]{1});

        assertNotNull(t.deriveByUid("SN123", BizType.DEVICE_ROOT));
        assertNotNull(t.wrapByUid("SN123", BizType.DEVICE_ROOT, new byte[]{1}));
        assertArrayEquals(new byte[]{1}, t.unwrapByUid("SN123", BizType.DEVICE_ROOT, new byte[]{99}));
    }
}
