package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceRecipient;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DefaultDataKeyDistributionTemplateTest {

    private KmsClient kmsClient;
    private CryptoMetrics cryptoMetrics;
    private DeviceResolver deviceResolver;
    private DefaultDataKeyDistributionTemplate template;

    @BeforeEach
    void setUp() {
        kmsClient = mock(KmsClient.class);
        cryptoMetrics = mock(CryptoMetrics.class);
        deviceResolver = mock(DeviceResolver.class);
        template = new DefaultDataKeyDistributionTemplate(kmsClient, cryptoMetrics, deviceResolver);
    }

    @Test
    void issue_supportsDataFalse_failClosed() {
        CryptoException ex = assertThrows(CryptoException.class,
                () -> template.issueActiveKeyForDevice("SN123", BizType.TBOX_DEVICE_ROOT,
                        new DeviceRecipient("cert-001")));
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE, ex.getReason());
        verify(kmsClient, never()).wrapActiveDataKeyForDevice(any(), any(), any());
    }

    @Test
    void issue_allCurrentBizTypes_failClosed() {
        for (BizType bt : BizType.values()) {
            if (bt.supportsData()) continue;
            assertThrows(CryptoException.class,
                    () -> template.issueActiveKeyForDevice("SN123", bt,
                            new DeviceRecipient("cert-001")),
                    "Should fail-closed for " + bt.name());
        }
        verify(kmsClient, never()).wrapActiveDataKeyForDevice(any(), any(), any());
    }

    @Test
    void issue_nullBizType_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.issueActiveKeyForDevice("SN123", null,
                        new DeviceRecipient("cert-001")));
    }

    @Test
    void issue_nullRecipient_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.issueActiveKeyForDevice("SN123", BizType.V2C_COMM_ROOT, null));
    }

    @Test
    void issue_nullDeviceSnOrVin_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.issueActiveKeyForDevice(null, BizType.V2C_COMM_ROOT,
                        new DeviceRecipient("cert-001")));
    }

    @Test
    void issue_blankDeviceSnOrVin_throwsCryptoException() {
        assertThrows(CryptoException.class,
                () -> template.issueActiveKeyForDevice("", BizType.V2C_COMM_ROOT,
                        new DeviceRecipient("cert-001")));
    }

    @Test
    void issue_vinButNoResolver_throws() {
        DefaultDataKeyDistributionTemplate t =
                new DefaultDataKeyDistributionTemplate(kmsClient, cryptoMetrics, null);

        assertThrows(CryptoException.class,
                () -> t.issueActiveKeyForDevice("VIN12345678901234", BizType.V2C_COMM_ROOT,
                        new DeviceRecipient("cert-001")));
    }
}
