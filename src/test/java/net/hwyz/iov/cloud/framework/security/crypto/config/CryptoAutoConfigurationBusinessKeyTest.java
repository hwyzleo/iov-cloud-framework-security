package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyDirectoryResolver;
import net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyMaterialTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.CryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultBusinessKeyMaterialTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultVmdBusinessKeyDirectoryResolver;
import net.hwyz.iov.cloud.framework.security.crypto.VmdBusinessKeyDirectoryClient;
import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyDescriptor;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.DeviceKeyContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyOperation;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * CryptoAutoConfiguration 业务密钥装配集成测试（FW-SEC-DSN-CR-009 §10/§12 集成）。
 * <p>
 * 验证：business-key.enabled 装配材料门面；directory.enabled 装配 Resolver Adapter
 * （缺 VMD Feign 客户端时启动 fail-closed）；CryptoTemplate 正确注入目录与材料门面。
 * 条件开关语义由 @ConditionalOnProperty 承担，此处验证 Bean 方法装配逻辑。
 */
class CryptoAutoConfigurationBusinessKeyTest {

    private final CryptoAutoConfiguration configuration = new CryptoAutoConfiguration();
    private final CryptoProperties properties = new CryptoProperties();
    private final KmsClient kmsClient = mock(KmsClient.class);
    private final CryptoMetrics cryptoMetrics = mock(CryptoMetrics.class);

    @Test
    void businessKeyMaterialTemplate_enabled_assemblesDefaultImpl() {
        BusinessKeyMaterialTemplate template = configuration.businessKeyMaterialTemplate(
                kmsClient, cryptoMetrics, properties);
        assertTrue(template instanceof DefaultBusinessKeyMaterialTemplate);
    }

    @Test
    void directoryResolver_withVmdClient_assemblesDefaultResolver() {
        VmdBusinessKeyDirectoryClient client = new VmdBusinessKeyDirectoryClient() {
            @Override
            public BusinessKeyDescriptor resolveActive(DeviceKeyContext context) {
                return descriptor();
            }

            @Override
            public BusinessKeyDescriptor resolveByKeyId(String keyId, KeyOperation operation) {
                return descriptor();
            }
        };

        BusinessKeyDirectoryResolver resolver =
                configuration.businessKeyDirectoryResolver(providerOf(client), cryptoMetrics);

        assertTrue(resolver instanceof DefaultVmdBusinessKeyDirectoryResolver);
        assertNotNull(resolver.resolveActive(new DeviceKeyContext("SN001", null, null, null)));
    }

    @Test
    void directoryResolver_withoutVmdClient_failsClosedAtStartup() {
        assertThrows(IllegalStateException.class,
                () -> configuration.businessKeyDirectoryResolver(
                        providerOf(null), cryptoMetrics));
    }

    @Test
    void cryptoTemplate_wiresDirectoryAndMaterial() {
        BusinessKeyDirectoryResolver directory = mock(BusinessKeyDirectoryResolver.class);
        BusinessKeyMaterialTemplate material = mock(BusinessKeyMaterialTemplate.class);
        DeviceResolver deviceResolver = mock(DeviceResolver.class);
        KeyCache keyCache = mock(KeyCache.class);
        AeadCipher aeadCipher = new AeadCipher();
        EnvelopeCodec envelopeCodec = new EnvelopeCodec();

        CryptoTemplate cryptoTemplate = configuration.cryptoTemplate(
                deviceResolver, keyCache, aeadCipher, envelopeCodec, cryptoMetrics, kmsClient,
                providerOf(directory), providerOf(material));

        assertTrue(cryptoTemplate instanceof DefaultCryptoTemplate);
    }

    @Test
    void cryptoTemplate_allowsDirectoryAbsent_forSessionOnlyConsumers() {
        BusinessKeyMaterialTemplate material = mock(BusinessKeyMaterialTemplate.class);
        CryptoTemplate cryptoTemplate = configuration.cryptoTemplate(
                mock(DeviceResolver.class), mock(KeyCache.class), new AeadCipher(), new EnvelopeCodec(),
                cryptoMetrics, kmsClient, providerOf(null), providerOf(material));
        assertNotNull(cryptoTemplate);
    }

    private BusinessKeyDescriptor descriptor() {
        return new BusinessKeyDescriptor("k-1", 1, "bk/k-1", CryptoKeyState.ACTIVE,
                Instant.parse("2026-10-01T00:00:00Z"), null, null);
    }

    private static <T> ObjectProvider<T> providerOf(T bean) {
        return new ObjectProvider<>() {
            @Override
            public T getObject() {
                return bean;
            }

            @Override
            public T getObject(Object... args) {
                return bean;
            }

            @Override
            public T getIfAvailable() {
                return bean;
            }

            @Override
            public T getIfUnique() {
                return bean;
            }
        };
    }
}
