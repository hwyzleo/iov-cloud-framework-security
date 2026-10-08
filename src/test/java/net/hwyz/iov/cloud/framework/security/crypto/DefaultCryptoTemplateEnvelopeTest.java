package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyDirectoryUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyStateNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyDescriptor;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.DeviceKeyContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyOperation;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * CryptoTemplate ENVELOPE 正反向寻址测试（FW-SEC-DSN-CR-009 §5/§12）。
 * <p>
 * 正向加密必须经 resolveActive；反向解密必须经 resolveByKeyId 且校验版本一致；
 * 目录不可用/拒绝时 fail-closed，禁止直连 KMS 按 keyId 降级（RD-009-6）。
 * <p>
 * 注：当前 BizType 权威清单无 supportsData=true 项（均 fail-closed），故正向 ENVELOPE
 * 路径通过包私有 {@link DefaultCryptoTemplate#encryptEnvelope} 直接验证寻址逻辑
 * （公开入口的 supportsData/cryptoMode 护栏由 {@code encrypt_envelope_provisionOnlyBizType_failClosed} 覆盖）。
 */
class DefaultCryptoTemplateEnvelopeTest {

    private DeviceResolver deviceResolver;
    private KeyCache keyCache;
    private AeadCipher aeadCipher;
    private EnvelopeCodec envelopeCodec;
    private CryptoMetrics cryptoMetrics;
    private KmsClient kmsClient;
    private BusinessKeyDirectoryResolver directoryResolver;
    private BusinessKeyMaterialTemplate materialTemplate;
    private DefaultCryptoTemplate template;

    @BeforeEach
    void setUp() {
        deviceResolver = mock(DeviceResolver.class);
        keyCache = mock(KeyCache.class);
        aeadCipher = new AeadCipher();
        envelopeCodec = new EnvelopeCodec();
        cryptoMetrics = mock(CryptoMetrics.class);
        kmsClient = mock(KmsClient.class);
        directoryResolver = mock(BusinessKeyDirectoryResolver.class);
        materialTemplate = mock(BusinessKeyMaterialTemplate.class);
        template = new DefaultCryptoTemplate(deviceResolver, keyCache, aeadCipher,
                envelopeCodec, cryptoMetrics, kmsClient, directoryResolver, materialTemplate);
    }

    private CachedDataKey dataKey(String keyId, int version, byte[] dek) {
        CachedDataKey dataKey = new CachedDataKey();
        dataKey.setKeyId(keyId);
        dataKey.setKeyVersion(version);
        dataKey.setDekPlaintext(dek);
        return dataKey;
    }

    private BusinessKeyDescriptor active(String keyId, long version) {
        return new BusinessKeyDescriptor(keyId, version, "bk/" + keyId, CryptoKeyState.ACTIVE,
                Instant.parse("2026-10-01T00:00:00Z"), null, null);
    }

    @Test
    void encryptEnvelope_goesThroughDirectoryAndWritesHeader() {
        byte[] dek = new byte[32];
        new java.security.SecureRandom().nextBytes(dek);
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.V2C_COMM_ROOT)).thenReturn("SN001");
        BusinessKeyDescriptor descriptor = active("k-1", 5);
        when(directoryResolver.resolveActive(any(DeviceKeyContext.class))).thenReturn(descriptor);
        when(keyCache.get(eq(descriptor), eq("SN001"), eq(BizType.V2C_COMM_ROOT), isNull(), eq(materialTemplate)))
                .thenReturn(dataKey("k-1", 5, dek));

        byte[] payload = template.encryptEnvelope("VIN123", BizType.V2C_COMM_ROOT, "hello".getBytes());

        assertNotNull(payload);
        CipherPayload decoded = envelopeCodec.decode(payload);
        assertEquals("k-1", decoded.getHeader().getKeyId());
        assertEquals(5, decoded.getHeader().getKeyVersion());
        verify(directoryResolver).resolveActive(argThat(ctx ->
                "SN001".equals(ctx.deviceSn()) && ctx.bizType() == BizType.V2C_COMM_ROOT));
    }

    @Test
    void encryptEnvelope_thenDecrypt_roundTrip() {
        byte[] dek = new byte[32];
        new java.security.SecureRandom().nextBytes(dek);
        byte[] plaintext = "round trip data".getBytes();

        when(deviceResolver.resolveDeviceSn("VIN123", BizType.V2C_COMM_ROOT)).thenReturn("SN001");
        BusinessKeyDescriptor descriptor = active("k-1", 5);
        when(directoryResolver.resolveActive(any(DeviceKeyContext.class))).thenReturn(descriptor);
        when(directoryResolver.resolveByKeyId("k-1", KeyOperation.DECRYPT)).thenReturn(descriptor);
        when(keyCache.get(eq(descriptor), eq("SN001"), eq(BizType.V2C_COMM_ROOT), isNull(), eq(materialTemplate)))
                .thenReturn(dataKey("k-1", 5, dek));
        when(keyCache.get(eq(descriptor), isNull(), isNull(), isNull(), eq(materialTemplate)))
                .thenReturn(dataKey("k-1", 5, dek));

        byte[] payload = template.encryptEnvelope("VIN123", BizType.V2C_COMM_ROOT, plaintext);
        byte[] result = template.decrypt(payload);

        assertArrayEquals(plaintext, result);
        verify(directoryResolver).resolveByKeyId("k-1", KeyOperation.DECRYPT);
    }

    @Test
    void decrypt_versionMismatch_rejected() {
        byte[] dek = new byte[32];
        new java.security.SecureRandom().nextBytes(dek);
        BusinessKeyDescriptor descriptor = active("k-1", 3);
        when(directoryResolver.resolveByKeyId("k-1", KeyOperation.DECRYPT)).thenReturn(descriptor);
        when(keyCache.get(eq(descriptor), isNull(), isNull(), isNull(), eq(materialTemplate)))
                .thenReturn(dataKey("k-1", 3, dek));

        // 手工构造信封头版本=2，与目录 businessKeyVersion=3 不一致
        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId("k-1");
        header.setKeyVersion(2);
        header.setAlg("AES_256_GCM");
        header.setIv(aeadCipher.generateIv());
        byte[] aad = envelopeCodec.encode(header, new byte[0]);
        byte[] ciphertext = aeadCipher.encrypt(new byte[0], dek, header.getIv(), aad);
        byte[] payload = envelopeCodec.encode(header, ciphertext);

        assertThrows(BusinessKeyStateNotAllowedException.class, () -> template.decrypt(payload));
        verify(keyCache, never()).get(any(), any(), any(), any(), any());
    }

    @Test
    void encryptEnvelope_withoutDirectory_failClosed() {
        DefaultCryptoTemplate noDirectory = new DefaultCryptoTemplate(deviceResolver, keyCache, aeadCipher,
                envelopeCodec, cryptoMetrics, kmsClient, null, materialTemplate);

        assertThrows(BusinessKeyDirectoryUnavailableException.class,
                () -> noDirectory.encryptEnvelope("VIN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
        // 不得降级直连 KMS 取钥
        verify(kmsClient, never()).getActiveDataKey(any(), any());
    }

    @Test
    void decrypt_withoutDirectory_failClosed() {
        DefaultCryptoTemplate noDirectory = new DefaultCryptoTemplate(deviceResolver, keyCache, aeadCipher,
                envelopeCodec, cryptoMetrics, kmsClient, null, materialTemplate);

        byte[] payload = buildEnvelope("k-1", 1, new byte[0], new byte[32]);

        assertThrows(BusinessKeyDirectoryUnavailableException.class, () -> noDirectory.decrypt(payload));
        verify(kmsClient, never()).getDataKeyById(any(), any());
    }

    @Test
    void encryptEnvelope_withoutMaterialTemplate_failClosed() {
        // 用真实 KeyCache：材料门面缺失时 KeyCache.get 抛 BusinessKeyDirectoryUnavailableException
        KeyCache realKeyCache = new KeyCache(new CryptoProperties(), kmsClient);
        realKeyCache.init();
        DefaultCryptoTemplate noMaterial = new DefaultCryptoTemplate(deviceResolver, realKeyCache, aeadCipher,
                envelopeCodec, cryptoMetrics, kmsClient, directoryResolver, null);
        when(deviceResolver.resolveDeviceSn("VIN123", BizType.V2C_COMM_ROOT)).thenReturn("SN001");
        when(directoryResolver.resolveActive(any(DeviceKeyContext.class))).thenReturn(active("k-1", 1));

        assertThrows(BusinessKeyDirectoryUnavailableException.class,
                () -> noMaterial.encryptEnvelope("VIN123", BizType.V2C_COMM_ROOT, new byte[]{1}));
    }

    @Test
    void encrypt_envelope_provisionOnlyBizType_failClosed() {
        // TBOX_DEVICE_ROOT supportsData=false，ENVELOPE 加密必须 fail-closed
        assertThrows(CryptoException.class,
                () -> template.encrypt("VIN123", BizType.TBOX_DEVICE_ROOT, new byte[]{1}));
        verify(directoryResolver, never()).resolveActive(any());
    }

    private byte[] buildEnvelope(String keyId, int version, byte[] plaintext, byte[] dek) {
        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId(keyId);
        header.setKeyVersion(version);
        header.setAlg("AES_256_GCM");
        header.setIv(aeadCipher.generateIv());
        byte[] aad = envelopeCodec.encode(header, new byte[0]);
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dek, header.getIv(), aad);
        return envelopeCodec.encode(header, ciphertext);
    }
}
