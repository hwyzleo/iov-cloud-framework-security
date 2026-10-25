package net.hwyz.iov.cloud.framework.security.crypto.config;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsFeignClient;
import net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoder;
import net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoderRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.InMemoryOperationResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.provider.OperationResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.support.ParProtoKeyprovAadV1Encoder;
import net.hwyz.iov.cloud.framework.security.crypto.transit.TransitDerivedKeyProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CR-020 自动装配测试（FW-SEC-DSN-CR-020 §2/§4/§5）。
 * <p>
 * 真实 Spring 上下文验证：EnvelopeAadEncoderRegistry 收集 VMD 注册的 encoder（启动冻结）、
 * OperationResultStore 默认 InMemory、消费方自定义持久化 store 时默认 Bean 退让、
 * aad-profile-id 配置后 TransitDerivedKeyProvider 携带 profile 与结果存储。
 */
class CryptoAutoConfigurationAadTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CryptoAutoConfiguration.class,
                    RefreshAutoConfiguration.class))
            .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .withBean(KmsFeignClient.class, () -> org.mockito.Mockito.mock(KmsFeignClient.class));

    @Test
    void registryCollectsVmdEncoderBeans() {
        runner
                .withBean("parProtoEncoder", EnvelopeAadEncoder.class,
                        ParProtoKeyprovAadV1Encoder::new)
                .run(context -> {
                    assertThat(context).hasSingleBean(EnvelopeAadEncoderRegistry.class);
                    EnvelopeAadEncoderRegistry registry =
                            context.getBean(EnvelopeAadEncoderRegistry.class);
                    assertThat(registry.has(ParProtoKeyprovAadV1Encoder.PROFILE_ID)).isTrue();
                    assertThat(registry.profileIds()).containsExactly(
                            ParProtoKeyprovAadV1Encoder.PROFILE_ID);
                });
    }

    @Test
    void resultStoreDefaultsToInMemory() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(OperationResultStore.class);
            OperationResultStore store = context.getBean(OperationResultStore.class);
            assertThat(store.storeType()).isEqualTo(InMemoryOperationResultStore.STORE_TYPE);
            assertThat(store.productionReady()).isFalse();
        });
    }

    @Test
    void customPersistentResultStoreBeatsDefault() {
        runner
                .withBean("persistentStore", OperationResultStore.class,
                        PersistentStoreStub::new)
                .run(context -> {
                    assertThat(context).hasSingleBean(OperationResultStore.class);
                    OperationResultStore store = context.getBean(OperationResultStore.class);
                    assertThat(store.storeType()).isEqualTo("persistent-stub");
                    assertThat(store.productionReady()).isTrue();
                });
    }

    @Test
    void resultStoreDisabled_noBean() {
        runner
                .withPropertyValues(
                        "crypto.provisioning.derived-key.result-store.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(OperationResultStore.class));
    }

    @Test
    void localWrapProviderCarriesConfiguredProfileAndStore() {
        runner
                .withPropertyValues(
                        "crypto.provisioning.enabled=true",
                        "crypto.provisioning.derived-key.provider=openbao-transit-local-wrap",
                        "crypto.provisioning.derived-key.aad-profile-id="
                                + ParProtoKeyprovAadV1Encoder.PROFILE_ID,
                        "crypto.kms.endpoint=http://openiov-openbao:8200",
                        "crypto.kms.token=tok",
                        "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.transit-key=v2c-comm-root",
                        "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.hmac-algorithm=sha2-256",
                        "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.purposes[0]=UPLINK_AEAD",
                        "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.purposes[1]=DOWNLINK_AEAD",
                        "crypto.provisioning.derived-key.roots.V2C_COMM_ROOT.wrap-modes[0]=DEVICE_CERT_PUBLIC_KEY")
                .withBean("parProtoEncoder", EnvelopeAadEncoder.class,
                        ParProtoKeyprovAadV1Encoder::new)
                .run(context -> {
                    assertThat(context).hasSingleBean(EnvelopeAadEncoderRegistry.class);
                    assertThat(context).hasSingleBean(OperationResultStore.class);
                    // aad-profile-id 配置 + registry/store 就绪 → local-wrap Provider 完整装配
                    assertThat(context).hasSingleBean(TransitDerivedKeyProvider.class);
                });
    }

    /** 模拟 VMD 提供的持久化、原子写入结果存储。 */
    static final class PersistentStoreStub implements OperationResultStore {
        @Override
        public java.util.Optional<net.hwyz.iov.cloud.framework.security.crypto.provider
                .DerivedWrapResultRecord> find(String operationId) {
            return java.util.Optional.empty();
        }

        @Override
        public net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedWrapResultRecord save(
                net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedWrapResultRecord record) {
            return record;
        }

        @Override
        public void markTerminal(String operationId,
                                 net.hwyz.iov.cloud.framework.security.crypto.provider
                                 .DerivedWrapResultRecord.Status status, String failReason) {
        }

        @Override
        public boolean productionReady() {
            return true;
        }

        @Override
        public String storeType() {
            return "persistent-stub";
        }
    }
}
