package net.hwyz.iov.cloud.framework.security.crypto.cache;

import net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyMaterialTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyDirectoryUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyDescriptor;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrappedBusinessKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * KeyCache 业务密钥取钥路径与缓存失效测试（FW-SEC-DSN-CR-009 §5/§8/§12）。
 */
class KeyCacheTest {

    private CryptoProperties properties;
    private KmsClient kmsClient;
    private BusinessKeyMaterialTemplate materialTemplate;
    private KeyCache keyCache;

    @BeforeEach
    void setUp() {
        properties = new CryptoProperties();
        properties.getBusinessKey().setRuntimeKeyName("runtime");
        kmsClient = mock(KmsClient.class);
        materialTemplate = mock(BusinessKeyMaterialTemplate.class);
        keyCache = new KeyCache(properties, kmsClient);
        keyCache.init();
    }

    private BusinessKeyDescriptor descriptor() {
        return new BusinessKeyDescriptor("k-1", 7, "bk/k-1", CryptoKeyState.ACTIVE,
                Instant.parse("2026-10-01T00:00:00Z"), null, null);
    }

    @Test
    void get_miss_fetchesViaRuntimeWrapAndUnwrap() {
        byte[] dek = new byte[32];
        new java.security.SecureRandom().nextBytes(dek);
        when(materialTemplate.wrap(eq(new net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyRef(
                        "k-1", "bk/k-1")),
                argThat(r -> r instanceof RecipientRef.RuntimeIdentity),
                argThat(ctx -> ctx.mode() == WrapMode.RUNTIME)))
                .thenReturn(new WrappedBusinessKey(new byte[]{1, 2, 3}, "k-1", 7, "AES", null, null));
        when(kmsClient.unwrap(eq("runtime"), any(WrappedKey.class))).thenReturn(dek);

        CachedDataKey dataKey = keyCache.get(descriptor(), "SN001", BizType.V2C_COMM_ROOT, "comm", materialTemplate);

        assertNotNull(dataKey);
        assertEquals("k-1", dataKey.getKeyId());
        assertEquals(7, dataKey.getKeyVersion());
        assertArrayEquals(dek, dataKey.getDekPlaintext());
        verify(materialTemplate).wrap(any(), any(), any());
        verify(kmsClient).unwrap(eq("runtime"), any(WrappedKey.class));
    }

    @Test
    void get_secondCall_cacheHit_noKmsCall() {
        byte[] dek = new byte[32];
        new java.security.SecureRandom().nextBytes(dek);
        when(materialTemplate.wrap(any(), any(), any()))
                .thenReturn(new WrappedBusinessKey(new byte[]{1}, "k-1", 7, "AES", null, null));
        when(kmsClient.unwrap(eq("runtime"), any(WrappedKey.class))).thenReturn(dek);

        keyCache.get(descriptor(), "SN001", BizType.V2C_COMM_ROOT, "comm", materialTemplate);
        keyCache.get(descriptor(), "SN001", BizType.V2C_COMM_ROOT, "comm", materialTemplate);

        verify(materialTemplate, times(1)).wrap(any(), any(), any());
    }

    @Test
    void get_nullMaterialTemplate_failClosed() {
        assertThrows(BusinessKeyDirectoryUnavailableException.class,
                () -> keyCache.get(descriptor(), "SN001", BizType.V2C_COMM_ROOT, "comm", null));
        verify(kmsClient, never()).unwrap(any(), any());
    }

    @Test
    void invalidateKey_removesMatchingEntries() {
        byte[] dek = new byte[32];
        when(materialTemplate.wrap(any(), any(), any()))
                .thenReturn(new WrappedBusinessKey(new byte[]{1}, "k-1", 7, "AES", null, null));
        when(kmsClient.unwrap(eq("runtime"), any(WrappedKey.class))).thenReturn(dek);

        keyCache.get(descriptor(), "SN001", BizType.V2C_COMM_ROOT, "comm", materialTemplate);
        keyCache.invalidateKey("k-1");
        keyCache.get(descriptor(), "SN001", BizType.V2C_COMM_ROOT, "comm", materialTemplate);

        // 失效后再次取钥应重新走 KMS（即 wrap 被调用 2 次）
        verify(materialTemplate, times(2)).wrap(any(), any(), any());
    }

    @Test
    void invalidateContext_matchesDeviceAndPurpose() {
        byte[] dek = new byte[32];
        when(materialTemplate.wrap(any(), any(), any()))
                .thenReturn(new WrappedBusinessKey(new byte[]{1}, "k-1", 7, "AES", null, null));
        when(kmsClient.unwrap(eq("runtime"), any(WrappedKey.class))).thenReturn(dek);

        keyCache.get(descriptor(), "SN001", BizType.V2C_COMM_ROOT, "comm", materialTemplate);

        // 命中其它设备/用途不失效
        keyCache.invalidateContext("SN999", BizType.V2C_COMM_ROOT, "comm");
        verify(materialTemplate, times(1)).wrap(any(), any(), any());

        // 命中目标上下文后失效，再次取钥重新走 KMS
        keyCache.invalidateContext("SN001", BizType.V2C_COMM_ROOT, "comm");
        keyCache.get(descriptor(), "SN001", BizType.V2C_COMM_ROOT, "comm", materialTemplate);
        verify(materialTemplate, times(2)).wrap(any(), any(), any());
    }
}
