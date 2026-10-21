package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * DERIVED_ROOT Provider 路由器测试（FW-SEC-DSN-CR-019 §4/§12）。
 * <p>
 * 启动静态选择；未知值启动 fail-closed；<strong>禁止</strong>请求失败后动态回退
 * （local-wrap 失败不得改走 legacy）。
 */
class DerivedKeyProviderRouterTest {

    private DerivedKeyCommand command() {
        return new DerivedKeyCommand(BizType.V2C_COMM_ROOT,
                KeyAnchor.vin("LSVAA4187N2123456"), KeyPurpose.UPLINK_AEAD,
                ValidatedRecipientEvidenceFixtures.evidenceOrThrow(
                        WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM),
                DerivationContext.v1(), new OperationContext("op-1", "idem-1"));
    }

    @Test
    void localWrap_routesToTransitProvider() {
        DerivedKeyProvider transit = mock(DerivedKeyProvider.class);
        DerivedKeyProvider legacy = mock(DerivedKeyProvider.class);
        DerivedWrappedKey result = new DerivedWrappedKey("l", "ref", 1L, "v1",
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                new byte[]{1}, new byte[]{2}, new byte[]{3}, "op");
        when(transit.deriveAndWrap(any())).thenReturn(result);
        when(transit.capability()).thenReturn(DerivedKeyCapability.ready("openbao-transit-local-wrap"));

        DerivedKeyProviderRouter router = new DerivedKeyProviderRouter(
                DerivedKeyProviderRouter.LOCAL_WRAP_PROVIDER, transit, null);
        assertEquals(result, router.deriveAndWrap(command()));
        verify(transit).deriveAndWrap(any());
        verify(legacy, never()).deriveAndWrap(any());
        assertEquals("openbao-transit-local-wrap", router.providerName());
    }

    @Test
    void legacy_routesToLegacyProvider() {
        DerivedKeyProvider transit = mock(DerivedKeyProvider.class);
        DerivedKeyProvider legacy = mock(DerivedKeyProvider.class);
        DerivedWrappedKey result = new DerivedWrappedKey("l", "ref", 1L, "v1",
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                new byte[]{1}, new byte[]{2}, new byte[]{3}, "op");
        when(legacy.deriveAndWrap(any())).thenReturn(result);

        DerivedKeyProviderRouter router = new DerivedKeyProviderRouter(
                DerivedKeyProviderRouter.LEGACY_PROVIDER, null, legacy);
        assertEquals(result, router.deriveAndWrap(command()));
        verify(transit, never()).deriveAndWrap(any());
        verify(legacy).deriveAndWrap(any());
    }

    @Test
    void unknownProviderValue_startupFailClosed() {
        assertThrows(IllegalStateException.class,
                () -> new DerivedKeyProviderRouter("bogus-provider", null, null));
    }

    @Test
    void localWrapWithoutTransitProvider_startupFailClosed() {
        assertThrows(IllegalStateException.class,
                () -> new DerivedKeyProviderRouter(
                        DerivedKeyProviderRouter.LOCAL_WRAP_PROVIDER, null, mock(DerivedKeyProvider.class)));
    }

    @Test
    void legacyWithoutLegacyProvider_startupFailClosed() {
        assertThrows(IllegalStateException.class,
                () -> new DerivedKeyProviderRouter(
                        DerivedKeyProviderRouter.LEGACY_PROVIDER, mock(DerivedKeyProvider.class), null));
    }
}
