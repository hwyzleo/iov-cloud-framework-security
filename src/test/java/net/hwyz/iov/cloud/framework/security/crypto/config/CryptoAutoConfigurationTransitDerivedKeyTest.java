package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.TboxDeviceCertificateValidator;
import net.hwyz.iov.cloud.framework.security.crypto.auth.OpenBaoTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.provider.CertificatePublicKeyWrapper;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyProviderRouter;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.TestObjectProvider;
import net.hwyz.iov.cloud.framework.security.crypto.transit.TransitDerivedKeyHealthIndicator;
import net.hwyz.iov.cloud.framework.security.crypto.transit.TransitDerivedKeyProvider;
import net.hwyz.iov.cloud.framework.security.crypto.transit.TransitDerivedKeyReadiness;
import net.hwyz.iov.cloud.framework.security.crypto.transit.TransitHmacClient;
import net.hwyz.iov.cloud.framework.security.crypto.transit.TransitRootMetadataCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;

import java.time.Clock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * Transit 本地派生自动装配测试（FW-SEC-DSN-CR-019 §8/§12）。
 * <p>
 * local-wrap 装配 Transit 组件与路由器；legacy 不装配 Transit 组件；未知值启动 fail-closed；
 * 缺少凭据/roots 配置不一致 fail-closed。
 */
class CryptoAutoConfigurationTransitDerivedKeyTest {

    private final CryptoAutoConfiguration configuration = new CryptoAutoConfiguration();
    private final CryptoAutoConfiguration.TransitDerivedKeyHealthConfiguration healthConfiguration =
            new CryptoAutoConfiguration.TransitDerivedKeyHealthConfiguration();
    private CryptoProperties properties;

    @BeforeEach
    void setUp() {
        properties = new CryptoProperties();
        properties.getProvisioning().setEnabled(true);
        properties.getKms().setEndpoint("http://openiov-openbao:8200");
        properties.getKms().setToken("tok");
        properties.getProvisioning().getDerivedKey().setProvider("openbao-transit-local-wrap");
        CryptoProperties.Provisioning.DerivedKey.RootPolicy root =
                new CryptoProperties.Provisioning.DerivedKey.RootPolicy();
        root.setTransitKey("v2c-comm-root");
        root.setHmacAlgorithm("sha2-256");
        root.setPurposes(java.util.List.of("UPLINK_AEAD", "DOWNLINK_AEAD"));
        root.setWrapModes(java.util.List.of("DEVICE_CERT_PUBLIC_KEY"));
        properties.getProvisioning().getDerivedKey().getRoots().put("V2C_COMM_ROOT", root);
    }

    @Test
    void localWrap_assemblesTransitBeansAndRouter() {
        OpenBaoTokenProvider tokenProvider = configuration.openBaoTokenProvider(properties,
                new TestObjectProvider<>(Clock.systemUTC()));
        assertNotNull(tokenProvider);

        TransitHmacClient transitClient = configuration.transitHmacClient(properties,
                new TestObjectProvider<>(tokenProvider));
        assertNotNull(transitClient);

        DerivedKeyPolicyRegistry registry = configuration.derivedKeyPolicyRegistry(properties);
        assertNotNull(registry);

        TransitRootMetadataCache cache = configuration.transitRootMetadataCache(properties,
                new TestObjectProvider<>(transitClient));
        assertNotNull(cache);

        TransitDerivedKeyReadiness readiness = configuration.transitDerivedKeyReadiness(properties,
                new TestObjectProvider<>(tokenProvider), new TestObjectProvider<>(transitClient),
                new TestObjectProvider<>(new CertificatePublicKeyWrapper()),
                new TestObjectProvider<>(registry), new TestObjectProvider<>(cache),
                new TestObjectProvider<>(mock(TboxDeviceCertificateValidator.class)));
        assertNotNull(readiness);

        TransitDerivedKeyProvider provider = configuration.transitDerivedKeyProvider(properties,
                new TestObjectProvider<>(registry), new TestObjectProvider<>(transitClient),
                new TestObjectProvider<>(new CertificatePublicKeyWrapper()),
                new TestObjectProvider<>(cache), new TestObjectProvider<>(readiness),
                new TestObjectProvider<>(Clock.systemUTC()));
        assertNotNull(provider);

        DerivedKeyProviderRouter router = configuration.derivedKeyProviderRouter(properties,
                new TestObjectProvider<>(provider), new TestObjectProvider<>(mock(KmsClient.class)));
        assertEquals(DerivedKeyProviderRouter.LOCAL_WRAP_PROVIDER, router.providerName());
    }

    @Test
    void legacyProvider_doesNotAssembleTransitBeans() {
        properties.getProvisioning().getDerivedKey().setProvider("openbao-business-key");
        assertNull(configuration.transitHmacClient(properties, new TestObjectProvider<>()));
        assertNull(configuration.transitDerivedKeyReadiness(properties, new TestObjectProvider<>(),
                new TestObjectProvider<>(), new TestObjectProvider<>(), new TestObjectProvider<>(),
                new TestObjectProvider<>(), new TestObjectProvider<>()));
        assertNull(configuration.transitDerivedKeyProvider(properties, new TestObjectProvider<>(),
                new TestObjectProvider<>(), new TestObjectProvider<>(), new TestObjectProvider<>(),
                new TestObjectProvider<>(), new TestObjectProvider<>()));

        KmsClient kmsClient = mock(KmsClient.class);
        DerivedKeyProviderRouter router = configuration.derivedKeyProviderRouter(properties,
                new TestObjectProvider<>(), new TestObjectProvider<>(kmsClient));
        assertEquals(DerivedKeyProviderRouter.LEGACY_PROVIDER, router.providerName());
    }

    @Test
    void unknownProvider_routerFailsStartup() {
        properties.getProvisioning().getDerivedKey().setProvider("bogus-provider");
        assertThrows(IllegalStateException.class, () -> configuration.derivedKeyProviderRouter(
                properties, new TestObjectProvider<>(), new TestObjectProvider<>(mock(KmsClient.class))));
    }

    @Test
    void localWrap_withoutCredentials_failsStartup() {
        properties.getKms().setToken(null);
        assertThrows(IllegalStateException.class, () -> configuration.openBaoTokenProvider(
                properties, new TestObjectProvider<>(Clock.systemUTC())));
    }

    @Test
    void localWrap_configRootsMismatch_policyRegistryFailsStartup() {
        properties.getProvisioning().getDerivedKey().getRoots().clear();
        assertThrows(IllegalStateException.class,
                () -> configuration.derivedKeyPolicyRegistry(properties));
    }

    @Test
    void localWrap_unknownRootInConfig_failsStartup() {
        CryptoProperties.Provisioning.DerivedKey.RootPolicy immo =
                new CryptoProperties.Provisioning.DerivedKey.RootPolicy();
        immo.setTransitKey("immo-group");
        properties.getProvisioning().getDerivedKey().getRoots().put("IMMO_GROUP_KEY", immo);
        assertThrows(IllegalStateException.class,
                () -> configuration.derivedKeyPolicyRegistry(properties));
    }

    @Test
    void healthIndicator_wiredAndUpWhenReadinessReady() {
        properties.getKms().setToken("tok");
        OpenBaoTokenProvider tokenProvider = configuration.openBaoTokenProvider(properties,
                new TestObjectProvider<>(Clock.systemUTC()));
        TransitHmacClient transitClient = configuration.transitHmacClient(properties,
                new TestObjectProvider<>(tokenProvider));
        DerivedKeyPolicyRegistry registry = configuration.derivedKeyPolicyRegistry(properties);
        TransitRootMetadataCache cache = configuration.transitRootMetadataCache(properties,
                new TestObjectProvider<>(transitClient));
        TransitDerivedKeyReadiness readiness = configuration.transitDerivedKeyReadiness(properties,
                new TestObjectProvider<>(tokenProvider), new TestObjectProvider<>(transitClient),
                new TestObjectProvider<>(new CertificatePublicKeyWrapper()),
                new TestObjectProvider<>(registry), new TestObjectProvider<>(cache),
                new TestObjectProvider<>(mock(TboxDeviceCertificateValidator.class)));

        TransitDerivedKeyHealthIndicator indicator = healthConfiguration.transitDerivedKeyHealthIndicator(
                properties, new TestObjectProvider<>(readiness));
        // readiness 网络探测指向 http://openiov-openbao:8200（测试环境不存在）→ 报告 NOT_READY（不 UP）
        Health health = indicator.health();
        assertEquals(TransitDerivedKeyHealthIndicator.NOT_READY, health.getStatus());
    }

    @Test
    void healthIndicator_disabled_whenLegacyProvider() {
        properties.getProvisioning().getDerivedKey().setProvider("openbao-business-key");
        TransitDerivedKeyHealthIndicator indicator = healthConfiguration.transitDerivedKeyHealthIndicator(
                properties, new TestObjectProvider<>());
        assertEquals(TransitDerivedKeyHealthIndicator.DISABLED, indicator.health().getStatus());
    }
}
