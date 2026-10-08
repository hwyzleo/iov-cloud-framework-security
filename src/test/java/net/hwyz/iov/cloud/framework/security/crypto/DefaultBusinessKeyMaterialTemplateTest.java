package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsCreateKeyCommand;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsKeyMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsKeyMetadata;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsKeyReference;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsRecipient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsRevocationResult;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyNotFoundException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyRevocationFailedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyWrapFailedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyCreateRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyMaterialPolicy;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RevocationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * BusinessKeyMaterialTemplate 默认实现单元测试（FW-SEC-DSN-CR-009 §12 创建/封装/吊销）。
 */
class DefaultBusinessKeyMaterialTemplateTest {

    private KmsClient kmsClient;
    private CryptoMetrics cryptoMetrics;
    private CryptoProperties properties;
    private DefaultBusinessKeyMaterialTemplate template;

    @BeforeEach
    void setUp() {
        kmsClient = mock(KmsClient.class);
        cryptoMetrics = mock(CryptoMetrics.class);
        properties = new CryptoProperties();
        properties.getProvisioning().setProvider("Vault-Transit");
        template = new DefaultBusinessKeyMaterialTemplate(kmsClient, cryptoMetrics, properties);
    }

    // ==================== create ====================

    @Test
    void create_firstTime_returnsMaterial() {
        when(kmsClient.createDataKey(any(KmsCreateKeyCommand.class)))
                .thenReturn(new KmsKeyMaterial("k-1", "bk/dev/biz/data-1", 7,
                        "Vault-Transit", "AES_256_GCM", "256",
                        Instant.parse("2026-10-01T00:00:00Z"), null));

        BusinessKeyMaterial material = template.create(
                new BusinessKeyCreateRequest(BizType.TBOX_DEVICE_ROOT,
                        KeyMaterialPolicy.of("AES_256_GCM", "256"), "idem-1", null));

        assertNotNull(material);
        assertEquals("k-1", material.keyId());
        assertEquals("bk/dev/biz/data-1", material.kmsKeyRef());
        assertEquals(7, material.kmsKeyVersion());
        assertEquals("Vault-Transit", material.provider());
        verify(kmsClient).createDataKey(any(KmsCreateKeyCommand.class));
        verify(cryptoMetrics).recordBusinessKeyCreate(anyLong());
    }

    @Test
    void create_idempotencyConflict_rethrows() {
        when(kmsClient.createDataKey(any(KmsCreateKeyCommand.class)))
                .thenThrow(new BusinessKeyIdempotencyConflictException("conflict"));

        assertThrows(BusinessKeyIdempotencyConflictException.class,
                () -> template.create(new BusinessKeyCreateRequest(BizType.TBOX_DEVICE_ROOT,
                        KeyMaterialPolicy.of("AES_256_GCM", "256"), "idem-1", null)));
    }

    @Test
    void create_outcomeUnknown_rethrows() {
        when(kmsClient.createDataKey(any(KmsCreateKeyCommand.class)))
                .thenThrow(new CryptoOperationOutcomeUnknownException("unknown"));

        assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> template.create(new BusinessKeyCreateRequest(BizType.TBOX_DEVICE_ROOT,
                        KeyMaterialPolicy.of("AES_256_GCM", "256"), "idem-1", null)));
    }

    @Test
    void create_genericFailure_wrapsToOutcomeUnknown() {
        when(kmsClient.createDataKey(any(KmsCreateKeyCommand.class)))
                .thenThrow(new IllegalStateException("boom"));

        CryptoOperationOutcomeUnknownException ex = assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> template.create(new BusinessKeyCreateRequest(BizType.TBOX_DEVICE_ROOT,
                        KeyMaterialPolicy.of("AES_256_GCM", "256"), "idem-1", null)));
        assertTrue(ex.getMessage().contains("idem-1"));
    }

    @Test
    void create_nullRequest_throwsNpe() {
        assertThrows(NullPointerException.class, () -> template.create(null));
    }

    // ==================== wrap ====================

    @Test
    void wrap_deviceCertificate_mode() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        when(kmsClient.wrapKey(any(KmsKeyReference.class), any(KmsRecipient.class)))
                .thenReturn(new KmsWrappedKey(new byte[]{1, 2, 3}, "k-1", 7, "RSA-OAEP", null, null));

        var wrapped = template.wrap(ref, new RecipientRef.DeviceCertificate("cert-001"),
                new WrapContext(WrapMode.DEVICE_CERT_PUBLIC_KEY, "idem-w", null));

        assertNotNull(wrapped);
        assertArrayEquals(new byte[]{1, 2, 3}, wrapped.wrapped());
        verify(kmsClient).wrapKey(eq(new KmsKeyReference("k-1", "bk/dev/biz/data-1")),
                argThat(r -> r.mode() == WrapMode.DEVICE_CERT_PUBLIC_KEY && "cert-001".equals(r.certSerial())));
        verify(cryptoMetrics).recordBusinessKeyWrap(anyLong());
    }

    @Test
    void wrap_runtimeIdentity_mode() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        when(kmsClient.wrapKey(any(KmsKeyReference.class), any(KmsRecipient.class)))
                .thenReturn(new KmsWrappedKey(new byte[]{9}, "k-1", 7, "AES", null, null));

        var wrapped = template.wrap(ref, new RecipientRef.RuntimeIdentity("runtime"),
                new WrapContext(WrapMode.RUNTIME, null, null));

        assertNotNull(wrapped);
        verify(kmsClient).wrapKey(any(KmsKeyReference.class),
                argThat(r -> r.mode() == WrapMode.RUNTIME && "runtime".equals(r.audience())));
    }

    @Test
    void wrap_deviceRoot_explicitWrappingKeyRef() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        when(kmsClient.wrapKey(any(KmsKeyReference.class), any(KmsRecipient.class)))
                .thenReturn(new KmsWrappedKey(new byte[]{5}, "k-1", 7, "AES", null, null));

        var wrapped = template.wrap(ref, new RecipientRef.DeviceRoot("tb-root"),
                new WrapContext(WrapMode.DEVICE_ROOT_KEK, null, null));

        assertNotNull(wrapped);
        verify(kmsClient).wrapKey(any(KmsKeyReference.class),
                argThat(r -> r.mode() == WrapMode.DEVICE_ROOT_KEK && "tb-root".equals(r.wrappingKeyRef())));
    }

    @Test
    void wrap_modeMismatch_failClosed() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        BusinessKeyWrapFailedException ex = assertThrows(BusinessKeyWrapFailedException.class,
                () -> template.wrap(ref, new RecipientRef.DeviceCertificate("cert-001"),
                        new WrapContext(WrapMode.RUNTIME, null, null)));
        assertTrue(ex.getMessage().contains("不一致"));
        verify(kmsClient, never()).wrapKey(any(), any());
    }

    @Test
    void wrap_nullRecipient_failClosed() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        assertThrows(NullPointerException.class,
                () -> template.wrap(ref, null, new WrapContext(WrapMode.DEVICE_CERT_PUBLIC_KEY, null, null)));
    }

    @Test
    void wrap_kmsRejected_wrapsToWrapFailed() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        when(kmsClient.wrapKey(any(KmsKeyReference.class), any(KmsRecipient.class)))
                .thenThrow(new IllegalStateException("cert revoked"));

        assertThrows(BusinessKeyWrapFailedException.class,
                () -> template.wrap(ref, new RecipientRef.DeviceCertificate("cert-001"),
                        new WrapContext(WrapMode.DEVICE_CERT_PUBLIC_KEY, null, null)));
    }

    // ==================== getMetadata ====================

    @Test
    void getMetadata_success() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        when(kmsClient.getKeyMetadata(any(KmsKeyReference.class)))
                .thenReturn(new KmsKeyMetadata("k-1", "bk/dev/biz/data-1", 7, "Vault-Transit",
                        "AES_256_GCM", "256", CryptoKeyState.ACTIVE,
                        Instant.parse("2026-10-01T00:00:00Z"), null, null));

        var meta = template.getMetadata(ref);
        assertNotNull(meta);
        assertEquals(CryptoKeyState.ACTIVE, meta.state());
        verify(cryptoMetrics).recordBusinessKeyMetadata(anyLong());
    }

    @Test
    void getMetadata_notFound_rethrows() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        when(kmsClient.getKeyMetadata(any(KmsKeyReference.class)))
                .thenThrow(new BusinessKeyNotFoundException("not found"));

        assertThrows(BusinessKeyNotFoundException.class, () -> template.getMetadata(ref));
    }

    // ==================== revoke ====================

    @Test
    void revoke_success() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        when(kmsClient.revokeKey(any(KmsKeyReference.class), anyString(), anyString()))
                .thenReturn(new KmsRevocationResult("k-1", CryptoKeyState.REVOKED, Instant.now()));

        var result = template.revoke(ref, new RevocationRequest("轮换", "idem-r"));

        assertNotNull(result);
        assertEquals(CryptoKeyState.REVOKED, result.state());
        verify(kmsClient).revokeKey(eq(new KmsKeyReference("k-1", "bk/dev/biz/data-1")),
                eq("轮换"), eq("idem-r"));
        verify(cryptoMetrics).recordBusinessKeyRevoke(anyLong());
    }

    @Test
    void revoke_outcomeUnknown_rethrows() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        when(kmsClient.revokeKey(any(KmsKeyReference.class), anyString(), anyString()))
                .thenThrow(new CryptoOperationOutcomeUnknownException("unknown"));

        assertThrows(CryptoOperationOutcomeUnknownException.class,
                () -> template.revoke(ref, new RevocationRequest("吊销", "idem-r")));
    }

    @Test
    void revoke_genericFailure_wrapsToRevocationFailed() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        when(kmsClient.revokeKey(any(KmsKeyReference.class), anyString(), anyString()))
                .thenThrow(new IllegalStateException("boom"));

        assertThrows(BusinessKeyRevocationFailedException.class,
                () -> template.revoke(ref, new RevocationRequest("吊销", "idem-r")));
    }

    @Test
    void revoke_nullIdempotencyKey_throwsNpe() {
        BusinessKeyRef ref = new BusinessKeyRef("k-1", "bk/dev/biz/data-1");
        assertThrows(NullPointerException.class,
                () -> template.revoke(ref, new RevocationRequest("吊销", null)));
    }
}
