package net.hwyz.iov.cloud.framework.security.crypto.config;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.TboxDeviceCertificateValidator;
import net.hwyz.iov.cloud.framework.security.crypto.auth.OpenBaoTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsFeignClient;
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
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * Transit 本地派生自动装配测试（FW-SEC-DSN-CR-019 §5.4/§8/§12，RD-019-9/10）。
 * <p>
 * <strong>真实 Spring 上下文（ApplicationContextRunner）</strong>验证：
 * <ul>
 *   <li>local-wrap 全链装配（Wrapper/Provider/Readiness 各且仅一个 Bean）；</li>
 *   <li>消费方自定义 Wrapper 时默认 Bean 正确退让，无重复 Bean；</li>
 *   <li>非 local-wrap Provider 不误装配 Transit 组件；</li>
 *   <li>缺 token/根映射（registry）时以稳定 reason 启动 fail-closed；</li>
 *   <li>AutoConfiguration imports 在发布构件中真实可用。</li>
 * </ul>
 * 并保留工厂方法级 fail-closed 单元测试（缺凭据、roots 不一致、未知 Provider、Health 映射）。
 */
class CryptoAutoConfigurationTransitDerivedKeyTest {

    private final CryptoAutoConfiguration configuration = new CryptoAutoConfiguration();
    private final CryptoAutoConfiguration.TransitDerivedKeyHealthConfiguration healthConfiguration =
            new CryptoAutoConfiguration.TransitDerivedKeyHealthConfiguration();
    private CryptoProperties properties;

    // ==================== 真实 Spring 上下文装配（RD-019-10） ====================

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CryptoAutoConfiguration.class,
                    RefreshAutoConfiguration.class))
            .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .withBean(KmsFeignClient.class, () -> mock(KmsFeignClient.class));

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

    private static String[] localWrapProperties() {
        return new String[]{
                "crypto.provisioning.enabled=true",
                "crypto.provisioning.derived-key.provider=openbao-transit-local-wrap",
                "crypto.provisioning.derived-key.require-ready-at-startup=false",
                "crypto.kms.endpoint=http://openiov-openbao:8200",
                "crypto.kms.token=tok",
                "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.transit-key=v2c-comm-root",
                "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.hmac-algorithm=sha2-256",
                "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.purposes[0]=UPLINK_AEAD",
                "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.purposes[1]=DOWNLINK_AEAD",
                "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.wrap-modes[0]=DEVICE_CERT_PUBLIC_KEY"
        };
    }

    @Test
    void localWrap_realSpringContext_assemblesSingleBeans() {
        runner.withPropertyValues(localWrapProperties()).run(context -> {
            // §5.4 / RD-019-10：Wrapper、Provider、Readiness 各且仅一个 Bean
            assertThat(context).hasSingleBean(CertificatePublicKeyWrapper.class);
            assertThat(context).hasSingleBean(TransitDerivedKeyProvider.class);
            assertThat(context).hasSingleBean(TransitDerivedKeyReadiness.class);
            assertThat(context).hasSingleBean(TransitHmacClient.class);
            assertThat(context).hasSingleBean(TransitRootMetadataCache.class);
            assertThat(context).hasSingleBean(DerivedKeyProviderRouter.class);
        });
    }

    @Test
    void localWrap_consumerCustomWrapper_defaultBeanBacksOff() {
        CertificatePublicKeyWrapper customWrapper = new CertificatePublicKeyWrapper();
        runner.withPropertyValues(localWrapProperties())
                .withBean("customWrapper", CertificatePublicKeyWrapper.class, () -> customWrapper)
                .run(context -> {
                    // 消费方自定义 Wrapper → FW-SEC 默认 Bean 退让，且仅一个 Bean（RD-019-9/10）
                    assertThat(context).hasSingleBean(CertificatePublicKeyWrapper.class);
                    assertThat(context.getBean(CertificatePublicKeyWrapper.class)).isSameAs(customWrapper);
                    assertThat(context).hasSingleBean(TransitDerivedKeyProvider.class);
                    assertThat(context).hasSingleBean(TransitDerivedKeyReadiness.class);
                });
    }

    @Test
    void nonLocalWrap_doesNotAssembleTransitProvider() {
        runner.withPropertyValues(
                "crypto.provisioning.enabled=true",
                "crypto.provisioning.derived-key.provider=openbao-business-key",
                "crypto.kms.endpoint=http://openiov-openbao:8200",
                "crypto.kms.token=tok")
                .run(context -> {
                    // 非 local-wrap 不误装配 Transit 组件（RD-019-7/§12），路由器仍按 legacy 装配
                    assertThat(context).doesNotHaveBean(CertificatePublicKeyWrapper.class);
                    assertThat(context).doesNotHaveBean(TransitDerivedKeyProvider.class);
                    assertThat(context).doesNotHaveBean(TransitDerivedKeyReadiness.class);
                    assertThat(context).doesNotHaveBean(TransitHmacClient.class);
                    assertThat(context).doesNotHaveBean(TransitRootMetadataCache.class);
                    assertThat(context).hasSingleBean(DerivedKeyProviderRouter.class);
                });
    }

    @Test
    void localWrap_missingToken_failsStartupWithStableReason() {
        // 缺凭据：openBaoTokenProvider 在 local-wrap 下以稳定 reason 启动 fail-closed
        runner.withPropertyValues(withoutToken(localWrapProperties())).run(context -> {
            Throwable startup = context.getStartupFailure();
            assertThat(startup).as("缺 token 必须启动 fail-closed").isNotNull();
            assertThat(rootCause(startup)).isInstanceOf(IllegalStateException.class);
            assertThat(rootCause(startup).getMessage()).contains("crypto.kms.approle");
        });
    }

    @Test
    void localWrap_missingRootConfig_failsStartupWithStableReason() {
        // 缺根映射：policy registry 一致性校验 fail-closed（不能新增/缺失任意 Transit Key）
        runner.withPropertyValues(
                "crypto.provisioning.enabled=true",
                "crypto.provisioning.derived-key.provider=openbao-transit-local-wrap",
                "crypto.provisioning.derived-key.require-ready-at-startup=false",
                "crypto.kms.endpoint=http://openiov-openbao:8200",
                "crypto.kms.token=tok").run(context -> {
            Throwable startup = context.getStartupFailure();
            assertThat(startup).as("缺根映射必须启动 fail-closed").isNotNull();
            assertThat(rootCause(startup)).isInstanceOf(IllegalStateException.class);
            assertThat(rootCause(startup).getMessage()).contains("roots.V2C_COMM_ROOT 缺失");
        });
    }

    @Test
    void autoConfigurationImports_availableInPublishedArtifact() throws Exception {
        try (var in = getClass().getClassLoader().getResourceAsStream(
                "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports")) {
            assertThat(in).as("AutoConfiguration.imports 必须在发布构件中真实可用").isNotNull();
            String content = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            assertThat(content)
                    .contains("net.hwyz.iov.cloud.framework.security.crypto.config.CryptoAutoConfiguration");
        }
    }

    // ==================== 工厂方法级 fail-closed 单元测试 ====================

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
    void unknownProvider_routerFailsStartup() {
        properties.getProvisioning().getDerivedKey().setProvider("bogus-provider");
        assertThrows(IllegalStateException.class, () -> configuration.derivedKeyProviderRouter(
                properties, new TestObjectProvider<>(), new TestObjectProvider<>(mock(KmsClient.class))));
    }

    @Test
    void healthIndicator_wiredAndNotReadyWhenReadinessDown() {
        OpenBaoTokenProvider tokenProvider = configuration.openBaoTokenProvider(properties,
                new TestObjectProvider<>(Clock.systemUTC()));
        assertNotNull(tokenProvider);
        TransitHmacClient transitClient = configuration.transitHmacClient(properties,
                new TestObjectProvider<>(tokenProvider));
        assertNotNull(transitClient);
        DerivedKeyPolicyRegistry registry = configuration.derivedKeyPolicyRegistry(properties);
        TransitRootMetadataCache cache = configuration.transitRootMetadataCache(properties,
                transitClient);
        TransitDerivedKeyReadiness readiness = configuration.transitDerivedKeyReadiness(properties,
                new TestObjectProvider<>(tokenProvider), new TestObjectProvider<>(transitClient),
                new CertificatePublicKeyWrapper(),
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

    // ==================== 工具 ====================

    private static String[] withoutToken(String[] props) {
        return Arrays.stream(props)
                .filter(p -> !p.startsWith("crypto.kms.token="))
                .toArray(String[]::new);
    }

    private static Throwable rootCause(Throwable t) {
        Throwable root = t;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        return root;
    }
}
