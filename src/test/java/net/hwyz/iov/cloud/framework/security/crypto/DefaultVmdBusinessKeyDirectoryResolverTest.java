package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyDirectoryUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyNotFoundException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyStateNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyDescriptor;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.DeviceKeyContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyOperation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * BusinessKeyDirectoryResolver fail-closed 契约测试（FW-SEC-DSN-CR-009 §12 目录）。
 */
class DefaultVmdBusinessKeyDirectoryResolverTest {

    private VmdBusinessKeyDirectoryClient client;
    private DefaultVmdBusinessKeyDirectoryResolver resolver;

    @BeforeEach
    void setUp() {
        client = mock(VmdBusinessKeyDirectoryClient.class);
        resolver = new DefaultVmdBusinessKeyDirectoryResolver(client, mock(CryptoMetrics.class));
    }

    private DeviceKeyContext ctx() {
        return new DeviceKeyContext("SN001", BizType.V2C_COMM_ROOT, "comm", null);
    }

    @Test
    void resolveActive_singleActive_ok() {
        BusinessKeyDescriptor descriptor = descriptor(CryptoKeyState.ACTIVE, null);
        when(client.resolveActive(any())).thenReturn(descriptor);

        assertEquals(descriptor, resolver.resolveActive(ctx()));
    }

    @Test
    void resolveActive_empty_failClosed() {
        when(client.resolveActive(any())).thenReturn(null);

        assertThrows(BusinessKeyDirectoryUnavailableException.class,
                () -> resolver.resolveActive(ctx()));
    }

    @Test
    void resolveActive_nonActive_failClosed() {
        when(client.resolveActive(any())).thenReturn(descriptor(CryptoKeyState.DEPRECATED, null));

        assertThrows(BusinessKeyStateNotAllowedException.class,
                () -> resolver.resolveActive(ctx()));
    }

    @Test
    void resolveActive_clientFailure_wrapsToDirectoryUnavailable() {
        when(client.resolveActive(any())).thenThrow(new IllegalStateException("vmd down"));

        assertThrows(BusinessKeyDirectoryUnavailableException.class,
                () -> resolver.resolveActive(ctx()));
    }

    @Test
    void resolveByKeyId_deprecatedWithinWindow_ok() {
        BusinessKeyDescriptor descriptor = descriptor(CryptoKeyState.DEPRECATED, Instant.now().plusSeconds(3600));
        when(client.resolveByKeyId("k-1", KeyOperation.DECRYPT)).thenReturn(descriptor);

        assertEquals(descriptor, resolver.resolveByKeyId("k-1", KeyOperation.DECRYPT));
    }

    @Test
    void resolveByKeyId_deprecatedPastWindow_rejected() {
        BusinessKeyDescriptor descriptor = descriptor(CryptoKeyState.DEPRECATED, Instant.now().minusSeconds(60));
        when(client.resolveByKeyId("k-1", KeyOperation.DECRYPT)).thenReturn(descriptor);

        assertThrows(BusinessKeyStateNotAllowedException.class,
                () -> resolver.resolveByKeyId("k-1", KeyOperation.DECRYPT));
    }

    @Test
    void resolveByKeyId_revoked_rejected() {
        when(client.resolveByKeyId("k-1", KeyOperation.DECRYPT))
                .thenReturn(descriptor(CryptoKeyState.REVOKED, null));

        assertThrows(BusinessKeyStateNotAllowedException.class,
                () -> resolver.resolveByKeyId("k-1", KeyOperation.DECRYPT));
    }

    @Test
    void resolveByKeyId_expired_rejected() {
        when(client.resolveByKeyId("k-1", KeyOperation.DECRYPT))
                .thenReturn(descriptor(CryptoKeyState.EXPIRED, null));

        assertThrows(BusinessKeyStateNotAllowedException.class,
                () -> resolver.resolveByKeyId("k-1", KeyOperation.DECRYPT));
    }

    @Test
    void resolveByKeyId_notFound() {
        when(client.resolveByKeyId("k-1", KeyOperation.DECRYPT)).thenReturn(null);

        assertThrows(BusinessKeyNotFoundException.class,
                () -> resolver.resolveByKeyId("k-1", KeyOperation.DECRYPT));
    }

    @Test
    void resolveByKeyId_clientFailure_wrapsToDirectoryUnavailable() {
        when(client.resolveByKeyId("k-1", KeyOperation.DECRYPT))
                .thenThrow(new IllegalStateException("vmd down"));

        assertThrows(BusinessKeyDirectoryUnavailableException.class,
                () -> resolver.resolveByKeyId("k-1", KeyOperation.DECRYPT));
    }

    private BusinessKeyDescriptor descriptor(CryptoKeyState state, Instant decryptUntil) {
        return new BusinessKeyDescriptor("k-1", 1, "bk/ref", state,
                Instant.parse("2026-10-01T00:00:00Z"), null, decryptUntil);
    }
}
