package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyDirectoryResolver;
import net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyMaterialTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.CertEncryptionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.CertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.CryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DataKeyDistributionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultBusinessKeyMaterialTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCertEncryptionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultDataKeyDistributionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultImportProofVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultKeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultSigningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultTboxDeviceCertificateValidator;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultVmdBusinessKeyDirectoryResolver;
import net.hwyz.iov.cloud.framework.security.crypto.ImportProofReadiness;
import net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerificationHealthIndicator;
import net.hwyz.iov.cloud.framework.security.crypto.KeyprovCertificateProfileHealthIndicator;
import net.hwyz.iov.cloud.framework.security.crypto.KeyprovReadiness;
import net.hwyz.iov.cloud.framework.security.crypto.KeyprovStartupReadinessVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.KeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.SigningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.TboxDeviceCertificateValidator;
import net.hwyz.iov.cloud.framework.security.crypto.VmdBusinessKeyDirectoryClient;
import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.client.DefaultKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.DefaultPkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.FeignKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsBusinessKeyHealthIndicator;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsBusinessKeyProviderReadiness;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsFeignClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.LegacyRestPkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiFeignClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalDerivedEnvelopeDigestVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedEnvelopeDigestVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateChainValidator;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.EnrollmentIdempotencyService;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.HttpStepCaApiClient;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.InMemoryCertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.JwkSignerRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.JwkStepCaTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.RedisCertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaApiClient;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaPkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaProfilePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaProfilePolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaProfileRouteResolver;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateReferenceDirectory;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolutionHealthIndicator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolutionValidator;
import net.hwyz.iov.cloud.framework.security.crypto.revocation.CertificateStatusChecker;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultCertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultDeviceResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.FailClosedCertResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.net.URI;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 加解密自动配置
 */
@AutoConfiguration
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(CryptoAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public EnvelopeCodec envelopeCodec() {
        return new EnvelopeCodec();
    }

    @Bean
    @ConditionalOnMissingBean
    public AeadCipher aeadCipher() {
        return new AeadCipher();
    }

    /**
     * 框架受信任时钟（FW-SEC-DSN-CR-016 §3）。
     * <p>
     * 供导入证明验签与证书证据校验统一取 {@code now}；默认系统 UTC，消费方/测试可提供自定义
     * {@link Clock} Bean 覆盖以固定验证时刻。
     */
    @Bean
    @ConditionalOnMissingBean
    public Clock cryptoTrustedClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.kms", name = "endpoint")
    public KmsClient kmsClient(CryptoProperties properties, KmsFeignClient kmsFeignClient,
                               CryptoMetrics cryptoMetrics) {
        return new FeignKmsClient(properties, kmsFeignClient, cryptoMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public KmsClient defaultKmsClient() {
        return new DefaultKmsClient();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto", name = "envelope-enabled", havingValue = "true", matchIfMissing = true)
    public DeviceResolver deviceResolver(CryptoProperties properties) {
        return new DefaultDeviceResolver(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public KeyCache keyCache(CryptoProperties properties, KmsClient kmsClient) {
        return new KeyCache(properties, kmsClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public CryptoMetrics cryptoMetrics(io.micrometer.core.instrument.MeterRegistry meterRegistry) {
        return new CryptoMetrics(meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto", name = "envelope-enabled", havingValue = "true", matchIfMissing = true)
    public CryptoTemplate cryptoTemplate(DeviceResolver deviceResolver, KeyCache keyCache,
                                         AeadCipher aeadCipher, EnvelopeCodec envelopeCodec,
                                         CryptoMetrics cryptoMetrics, KmsClient kmsClient,
                                         ObjectProvider<BusinessKeyDirectoryResolver> directoryResolverProvider,
                                         ObjectProvider<BusinessKeyMaterialTemplate> materialTemplateProvider) {
        return new DefaultCryptoTemplate(deviceResolver, keyCache, aeadCipher, envelopeCodec,
                cryptoMetrics, kmsClient,
                directoryResolverProvider.getIfAvailable(),
                materialTemplateProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.business-key", name = "enabled", havingValue = "true")
    public BusinessKeyMaterialTemplate businessKeyMaterialTemplate(KmsClient kmsClient,
                                                                   CryptoMetrics cryptoMetrics,
                                                                   CryptoProperties properties,
                                                                   ObjectProvider<CertResolver> certResolverProvider,
                                                                   ObjectProvider<CertificateEvidenceValidator> evidenceValidatorProvider) {
        return new DefaultBusinessKeyMaterialTemplate(kmsClient, cryptoMetrics, properties,
                certResolverProvider.getIfAvailable(), evidenceValidatorProvider.getIfAvailable());
    }

    /**
     * 业务密钥 Provider 能力门禁与就绪状态（FW-SEC-DSN-CR-011 §7/§8.3）。
     * <p>
     * 受 {@code crypto.kms.business-key.enabled} 控制（仅 Provider 适配），与公共门面开关
     * {@code crypto.business-key.enabled} 区分。require-ready-at-startup=true 且 capability 未 READY 时
     * 启动 fail-closed；同时注册 provider-ready gauge 供 VMD keyprov readiness 与运维门禁使用。
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.kms.business-key", name = "enabled", havingValue = "true")
    public KmsBusinessKeyProviderReadiness kmsBusinessKeyProviderReadiness(KmsClient kmsClient,
                                                                           CryptoProperties properties,
                                                                           CryptoMetrics cryptoMetrics) {
        KmsBusinessKeyProviderReadiness readiness =
                new KmsBusinessKeyProviderReadiness(kmsClient, properties, cryptoMetrics);
        cryptoMetrics.registerBusinessKeyProviderReadyGauge(() -> readiness.isReady() ? 1 : 0);
        if (properties.getKms().getBusinessKey().isRequireReadyAtStartup()) {
            readiness.verifyAtStartup();
        }
        return readiness;
    }

    /**
     * 业务密钥目录 Resolver Adapter（FW-SEC-DSN-CR-009 §4/§10）。
     * <p>
     * 受 {@code crypto.business-key.directory.enabled} 控制；委托消费服务提供的
     * {@link VmdBusinessKeyDirectoryClient}（Feign 接入 VMD Service API，不内置 VMD 数据表）。
     * 目录不可用时 CryptoTemplate 正反向寻址 fail-closed，不得直连 KMS 降级（RD-009-6）。
     */
    @Bean
    @ConditionalOnMissingBean(BusinessKeyDirectoryResolver.class)
    @ConditionalOnProperty(prefix = "crypto.business-key.directory", name = "enabled", havingValue = "true")
    public BusinessKeyDirectoryResolver businessKeyDirectoryResolver(
            ObjectProvider<VmdBusinessKeyDirectoryClient> clientProvider,
            CryptoMetrics cryptoMetrics) {
        VmdBusinessKeyDirectoryClient client = clientProvider.getIfAvailable();
        if (client == null) {
            throw new IllegalStateException(
                    "crypto.business-key.directory.enabled=true 需要消费服务提供 VmdBusinessKeyDirectoryClient"
                            + "（Feign 接入 VMD Service API）。framework 只定义 SPI 与 Feign Adapter 扩展点，"
                            + "不内置 VMD 数据表（FW-SEC-DSN-CR-009 §4）。");
        }
        log.info("业务密钥目录 Resolver Adapter 装配完成: client={}", client.getClass().getSimpleName());
        return new DefaultVmdBusinessKeyDirectoryResolver(client, cryptoMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.provisioning", name = "enabled", havingValue = "true")
    public KeyProvisioningTemplate keyProvisioningTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics,
                                                           CryptoProperties properties,
                                                           ObjectProvider<DeviceResolver> deviceResolverProvider,
                                                           ObjectProvider<CertResolver> certResolverProvider,
                                                           ObjectProvider<CertificateEvidenceValidator> evidenceValidatorProvider,
                                                           ObjectProvider<TboxDeviceCertificateValidator> tboxValidatorProvider) {
        return new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties,
                deviceResolverProvider.getIfAvailable(),
                certResolverProvider.getIfAvailable(),
                evidenceValidatorProvider.getIfAvailable(),
                tboxValidatorProvider.getIfAvailable());
    }

    /**
     * 统一 TBOX 设备证书 Profile 验证器（FW-SEC-DSN-CR-017 §4/§7/§8；FW-SEC-DSN-CR-018 §9.1）。
     * <p>
     * 受 {@code crypto.keyprov.certificate-profile.enabled} 控制，与 provisioning/import-proof
     * 独立装配（决策 3）。装配时供 deriveAndWrap 与 ImportProofVerifier 经 ObjectProvider 消费；
     * 工厂方法<strong>纯构造</strong>，不再调用 readiness（RD-018-6）：启动强校验由独立
     * {@link KeyprovStartupReadinessVerifier} 在普通 singleton 创建完成后执行，消除
     * validator↔readiness 创建期循环依赖。
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.keyprov.certificate-profile", name = "enabled", havingValue = "true")
    public TboxDeviceCertificateValidator tboxDeviceCertificateValidator(
            ObjectProvider<CertResolver> certResolverProvider,
            ObjectProvider<CertificateEvidenceValidator> evidenceValidatorProvider,
            CryptoProperties properties,
            ObjectProvider<Clock> clockProvider) {
        log.info("统一 TBOX 设备证书 Profile 验证器装配完成: profile=TBOX_DEVICE_ECDH_ES_P256_V1");
        return new DefaultTboxDeviceCertificateValidator(certResolverProvider.getIfAvailable(),
                evidenceValidatorProvider.getIfAvailable(), properties, clockProvider.getIfAvailable());
    }

    /**
     * Keyprov 启动就绪强校验器（FW-SEC-DSN-CR-018 §9.2）。
     * <p>
     * 使用 {@link org.springframework.beans.factory.SmartInitializingSingleton}：回调发生在普通
     * singleton 创建完成后、应用 READY 之前；失败抛异常终止启动。readiness 可运行时延迟取得 validator，
     * validator 永不反向依赖 readiness（RD-018-6/7）。不启用 Spring 循环引用兼容开关。
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.keyprov.certificate-profile", name = "enabled", havingValue = "true")
    public KeyprovStartupReadinessVerifier keyprovStartupReadinessVerifier(
            ObjectProvider<KeyprovReadiness> readinessProvider,
            CryptoProperties properties) {
        KeyprovReadiness readiness = readinessProvider.getIfAvailable();
        if (readiness == null) {
            throw new IllegalStateException(
                    "KeyprovReadiness bean is not wired; cannot perform startup readiness verification"
                            + " (FW-SEC-DSN-CR-018 §9.2)");
        }
        return new KeyprovStartupReadinessVerifier(readiness,
                properties.getKeyprov().getCertificateProfile().isRequireReadyAtStartup());
    }

    /**
     * Keyprov 证书 Profile / 完整 ECDH-ES v1 聚合就绪（FW-SEC-DSN-CR-017 §9）。
     * <p>
     * 恒装配（诊断用）：未启用时报告 DISABLED 原因；完整 {@code KEYPROV_ECDH_ES_V1_READY}
     * 必须聚合 certificate-profile + provisioning + import-proof 及 envelope/verifier 能力。
     */
    @Bean
    @ConditionalOnMissingBean
    public KeyprovReadiness keyprovReadiness(CryptoProperties properties,
                                             ObjectProvider<TboxDeviceCertificateValidator> validatorProvider,
                                             ObjectProvider<Clock> clockProvider,
                                             ObjectProvider<CertResolver> certResolverProvider,
                                             Environment environment) {
        boolean revocationEnabled = Boolean.TRUE.equals(
                environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false));
        return new KeyprovReadiness(properties, validatorProvider, clockProvider,
                certResolverProvider.getIfAvailable(), revocationEnabled);
    }

    /**
     * 公开 canonical envelope digest verifier（FW-SEC-DSN-CR-015 §4.3/§7）。
     * <p>
     * 入参只能是公开 {@code DerivedWrappedKeyEnvelopeView}；由 core canonical codec 从 view 重建
     * 唯一 {@code envelopeDigest} 并恒定时间比较。与派生封装门面同开关（{@code crypto.provisioning.enabled}）。
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.provisioning", name = "enabled", havingValue = "true")
    public DerivedEnvelopeDigestVerifier derivedEnvelopeDigestVerifier() {
        return CanonicalDerivedEnvelopeDigestVerifier.instance();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.key-prov", name = "enabled", havingValue = "true")
    public DataKeyDistributionTemplate dataKeyDistributionTemplate(KmsClient kmsClient,
                                                                     CryptoMetrics cryptoMetrics,
                                                                     ObjectProvider<DeviceResolver> deviceResolverProvider) {
        return new DefaultDataKeyDistributionTemplate(kmsClient, cryptoMetrics,
                deviceResolverProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.signing", name = "enabled", havingValue = "true")
    public SigningTemplate signingTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics) {
        return new DefaultSigningTemplate(kmsClient, cryptoMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    public CertificateEvidenceValidator certificateEvidenceValidator(
            ObjectProvider<PkiClient> pkiClientProvider, CryptoProperties properties,
            ObjectProvider<Clock> clockProvider) {
        return new CertificateEvidenceValidator(pkiClientProvider, properties,
                clockProvider.getIfAvailable());
    }

    /**
     * 导入证明验签能力就绪门禁（FW-SEC-DSN-CR-016 §8）。
     * <p>
     * 校验 capability 静态自检、CertResolver 可用性与证书解析配置自洽；供 Health 与
     * {@code require-ready-at-startup} 启动门禁复用。
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.import-proof", name = "enabled", havingValue = "true")
    public ImportProofReadiness importProofReadiness(CertResolver certResolver,
                                                     CryptoProperties properties,
                                                     Environment environment) {
        boolean revocationEnabled = Boolean.TRUE.equals(
                environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false));
        return new ImportProofReadiness(properties, certResolver, revocationEnabled);
    }

    /**
     * 导入证明验证门面（FW-SEC-DSN-CR-016 §3/§8）。
     * <p>
     * 受 {@code crypto.import-proof.enabled} 控制；<strong>不</strong>复用
     * {@code crypto.provisioning.enabled}（发布顺序/依赖/故障影响不同）。
     * {@code require-ready-at-startup=true} 且 capability 未 READY 时启动 fail-closed。
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.import-proof", name = "enabled", havingValue = "true")
    public ImportProofVerifier importProofVerifier(CertResolver certResolver,
                                                   ObjectProvider<CertificateEvidenceValidator> evidenceValidatorProvider,
                                                   CryptoProperties properties,
                                                   CryptoMetrics cryptoMetrics,
                                                   ImportProofReadiness importProofReadiness,
                                                   ObjectProvider<Clock> clockProvider,
                                                   ObjectProvider<TboxDeviceCertificateValidator> tboxValidatorProvider) {
        if (properties.getImportProof().isRequireReadyAtStartup()) {
            importProofReadiness.verifyAtStartup();
        }
        return new DefaultImportProofVerifier(certResolver, evidenceValidatorProvider.getIfAvailable(),
                properties, cryptoMetrics, clockProvider.getIfAvailable(),
                tboxValidatorProvider.getIfAvailable());
    }

    /**
     * 证书解析门面（FW-SEC-DSN-CR-012 §5/§8）：
     * 启用 {@code crypto.pki.certificate-resolution.enabled=true} 且无自定义 Bean 时装配默认解析编排；
     * 否则装配 fail-closed 实现（不创建可误用的 Noop / 放行实现）。
     */
    @Bean
    @ConditionalOnMissingBean
    public CertResolver certResolver(CryptoProperties properties,
                                     CryptoMetrics cryptoMetrics,
                                     ObjectProvider<CertificateEnrollmentResultStore> resultStoreProvider,
                                     ObjectProvider<CertEnrollmentTemplate> enrollmentTemplateProvider,
                                     ObjectProvider<PkiClient> pkiClientProvider,
                                     ObjectProvider<CertificateReferenceDirectory> directoryProvider,
                                     Environment environment) {
        CryptoProperties.Pki.CertificateResolution config = properties.getPki().getCertificateResolution();
        if (!config.isEnabled()) {
            return new FailClosedCertResolver();
        }
        boolean revocationEnabled = Boolean.TRUE.equals(
                environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false));
        CertificateResolutionValidator.validate(properties, revocationEnabled);
        log.info("证书解析门面装配完成: providerQuery={}, domainDirectory={}, trustAnchorsConfigured={}",
                config.isProviderQueryEnabled(), config.isDomainDirectoryEnabled(),
                config.getTrustAnchorsPem() != null && !config.getTrustAnchorsPem().isBlank());
        return new DefaultCertResolver(resultStoreProvider,
                enrollmentTemplateProvider, pkiClientProvider, directoryProvider, properties,
                cryptoMetrics);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.pki", name = "endpoint")
    public CertEncryptionTemplate certEncryptionTemplate(CryptoMetrics cryptoMetrics,
                                                           ObjectProvider<CertResolver> certResolverProvider,
                                                           ObjectProvider<CertificateEvidenceValidator> evidenceValidatorProvider) {
        return new DefaultCertEncryptionTemplate(cryptoMetrics, certResolverProvider.getIfAvailable(),
                evidenceValidatorProvider.getIfAvailable());
    }

    // ==================== 证书注册：结果存储（FW-SEC-DSN-CR-008 §5.1） ====================

    /**
     * 证书注册结果存储：检测到 Redis（StringRedisTemplate）时自动装配共享可恢复实现；
     * 否则使用进程内有界实现（仅开发/测试，生产 profile + step-ca 时拒绝启动）。
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.pki", name = "endpoint")
    public CertificateEnrollmentResultStore certificateEnrollmentResultStore(
            ObjectProvider<StringRedisTemplate> redisTemplateProvider,
            CryptoProperties properties) {
        StringRedisTemplate redisTemplate = redisTemplateProvider.getIfAvailable();
        CryptoProperties.Pki.StepCa stepCa = properties.getPki().getStepCa();
        if (redisTemplate != null) {
            log.info("装配 Redis 证书注册结果存储: ttl={}", stepCa.getStoreTtl());
            return new RedisCertificateEnrollmentResultStore(redisTemplate, stepCa.getStoreTtl());
        }
        log.info("未检测到 Redis，装配进程内证书注册结果存储（仅开发/测试）: ttl={}", stepCa.getStoreTtl());
        return new InMemoryCertificateEnrollmentResultStore(stepCa.getStoreTtl(), 1000);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.pki", name = "endpoint")
    public EnrollmentIdempotencyService enrollmentIdempotencyService(
            CertificateEnrollmentResultStore resultStore) {
        return new EnrollmentIdempotencyService(resultStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public CertificateChainValidator certificateChainValidator() {
        return new CertificateChainValidator();
    }

    // ==================== 证书注册：provider 选择（FW-SEC-DSN-CR-008 §2.1/§8） ====================

    /**
     * step-ca 提供方：必须显式配置 crypto.pki.provider=step-ca 才装配。
     * 启动时校验 HTTPS scheme、根指纹与生产存储要求。
     */
    @Bean
    @ConditionalOnProperty(prefix = "crypto.pki", name = "provider", havingValue = "step-ca")
    public PkiClient stepCaPkiClient(CryptoProperties properties,
                                     CertificateEnrollmentResultStore resultStore,
                                     EnrollmentIdempotencyService idempotencyService,
                                     CertificateChainValidator chainValidator,
                                     CryptoMetrics cryptoMetrics,
                                     Environment environment,
                                     ObjectProvider<CertificateStatusChecker> certificateStatusCheckerProvider) {
        CryptoProperties.Pki pki = properties.getPki();
        CryptoProperties.Pki.StepCa stepCa = pki.getStepCa();

        // 启动校验（fail-fast：全部配置校验在网络调用之前完成）
        URI endpoint = URI.create(pki.getEndpoint());
        if (!"https".equalsIgnoreCase(endpoint.getScheme())) {
            throw new IllegalStateException(
                    "crypto.pki.endpoint must be HTTPS for step-ca provider, got: " + endpoint
                            + " (FW-SEC-DSN-CR-008 §2.1)");
        }
        if (stepCa.getRootSha256() == null || stepCa.getRootSha256().isBlank()) {
            throw new IllegalStateException("crypto.pki.step-ca.root-sha256 is required for step-ca provider");
        }
        if (resultStore instanceof InMemoryCertificateEnrollmentResultStore && isProductionProfile(environment)) {
            throw new IllegalStateException(
                    "step-ca requires a shared/persistent enrollment result store (Redis) in production; "
                            + "in-memory store is only for dev/test (FW-SEC-DSN-CR-008 §5.1)");
        }

        // FW-SEC-DSN-CR-018 §6/§8：启动构建不可变 signer registry（加载/解密 JWK、校验来源与算法），
        // 每个启用 Profile 必须可解析到且仅解析到一个 signer（§8.2），fail-closed（网络调用前）。
        JwkSignerRegistry signerRegistry = StepCaJwkSignerRegistryFactory.create(stepCa);
        StepCaProfilePolicyRegistry registry = stepCaProfilePolicyRegistry(stepCa);
        for (String profileName : registry.profileNames()) {
            StepCaProfileRouteResolver.resolve(registry.resolve(profileName), signerRegistry);
        }

        // step-ca API 客户端（启动即建立根指纹固定信任锚）
        StepCaApiClient apiClient = new HttpStepCaApiClient(
                endpoint, stepCa.getRootSha256(),
                pki.getConnectTimeout(), pki.getReadTimeout(),
                pki.getRetry().getMaxAttempts(), pki.getRetry().getBaseBackoff());

        StepCaTokenProvider tokenProvider = new JwkStepCaTokenProvider(signerRegistry, stepCa.getTokenTtl());

        PkiClient client = new StepCaPkiClient(
                apiClient, tokenProvider, signerRegistry, registry, resultStore, chainValidator,
                idempotencyService, cryptoMetrics, endpoint, stepCa.getRootSha256(),
                certificateStatusCheckerProvider.getIfAvailable());

        log.info("step-ca 证书注册装配完成: provider=step-ca, endpoint={}, rootFingerprint=...{}, "
                        + "resultStore={}, profiles={}, signers={}",
                endpoint.getHost(),
                stepCa.getRootSha256().replace(":", "").substring(
                        Math.max(0, stepCa.getRootSha256().replace(":", "").length() - 8)),
                resultStore.getClass().getSimpleName(), registry.profileNames(), signerRegistry.signerRefs());
        return client;
    }

    /**
     * legacy-rest 提供方：默认（未配置 provider 时保持存量行为）。
     */
    @Bean
    @ConditionalOnMissingBean(PkiClient.class)
    @ConditionalOnProperty(prefix = "crypto.pki", name = "endpoint")
    @ConditionalOnExpression("'${crypto.pki.provider:legacy-rest}' == 'legacy-rest'")
    public PkiClient legacyRestPkiClient(CryptoProperties properties, PkiFeignClient pkiFeignClient,
                                         ObjectProvider<CertificateStatusChecker> certificateStatusCheckerProvider) {
        CryptoProperties.Pki pki = properties.getPki();
        log.info("legacy-rest 证书注册装配完成: endpoint={}", pki.getEndpoint());
        return new LegacyRestPkiClient(properties, pkiFeignClient,
                certificateStatusCheckerProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean(PkiClient.class)
    public PkiClient defaultPkiClient() {
        return new DefaultPkiClient();
    }

    // ==================== 证书注册：门面（FW-SEC-DSN-CR-008 §5） ====================

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.pki", name = "endpoint")
    @ConditionalOnExpression("${crypto.pki.enrollment.enabled:true}")
    public CertEnrollmentTemplate certEnrollmentTemplate(
            PkiClient pkiClient,
            CryptoMetrics cryptoMetrics,
            CertificateEnrollmentResultStore resultStore,
            EnrollmentIdempotencyService idempotencyService,
            CertificateChainValidator chainValidator,
            @org.springframework.beans.factory.annotation.Autowired(required = false) List<CertificateProfile> allowedProfiles) {
        return new DefaultCertEnrollmentTemplate(pkiClient, cryptoMetrics,
                allowedProfiles != null ? allowedProfiles : List.of(),
                resultStore, idempotencyService, chainValidator);
    }

    /**
     * 受治理证书 profile 注册表（FW-SEC-DSN-CR-007 §2）
     * <p>
     * 作为 {@link CertificateProfile} Bean 注入容器，被 {@link DefaultCertEnrollmentTemplate#apply}
     * 的 allowedProfiles 白名单收集。name 须与业务方（VMD TBOX 设备证书申请）提交的 profile 名一致，
     * 否则将整体 fail-closed 拒绝。新增或修改 profile 走 CR + framework 发版。
     */
    @Bean
    public CertificateProfile tboxTspClientCertificateProfile() {
        return new CertificateProfile(
                "TBOX_TSP_CLIENT",
                "TBOX_TSP_CLIENT",
                CertificateProfile.SubjectType.DEVICE_IDENTITY,
                "EC",
                "TBOX 设备身份证书");
    }

    /**
     * 业务密钥 Provider 健康指示（FW-SEC-DSN-CR-011 §8.3）。
     * capability 未 READY 时 actuator 报告 DOWN，供 VMD keyprov readiness 门禁使用。
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(org.springframework.boot.actuate.health.HealthIndicator.class)
    @ConditionalOnProperty(prefix = "crypto.kms.business-key", name = "enabled", havingValue = "true")
    public static class KmsBusinessKeyHealthConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public KmsBusinessKeyHealthIndicator kmsBusinessKeyHealthIndicator(
                KmsBusinessKeyProviderReadiness readiness) {
            return new KmsBusinessKeyHealthIndicator(readiness);
        }
    }

    /**
     * 证书解析能力健康（FW-SEC-DSN-CR-012 §8）：启用解析能力时暴露配置缺口（如缺信任锚）为 NOT_READY。
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(org.springframework.boot.actuate.health.HealthIndicator.class)
    @ConditionalOnProperty(prefix = "crypto.pki.certificate-resolution", name = "enabled", havingValue = "true")
    public static class CertificateResolutionHealthConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public CertificateResolutionHealthIndicator certificateResolutionHealthIndicator(
                CryptoProperties properties, Environment environment,
                ObjectProvider<CertificateEnrollmentResultStore> resultStoreProvider,
                ObjectProvider<PkiClient> pkiClientProvider,
                ObjectProvider<CertificateReferenceDirectory> directoryProvider) {
            boolean revocationEnabled = Boolean.TRUE.equals(
                    environment.getProperty("crypto.pki.revocation.enabled", Boolean.class, false));
            return new CertificateResolutionHealthIndicator(properties, revocationEnabled,
                    resultStoreProvider.getIfAvailable() != null,
                    pkiClientProvider.getIfAvailable() != null,
                    directoryProvider.getIfAvailable() != null);
        }
    }

    /**
     * 导入证明验签能力健康（FW-SEC-DSN-CR-016 §8）：未启用报告 DISABLED，启用则按就绪情况
     * 报告 NOT_READY/UP，供 VMD keyprov activation 门禁使用。
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(org.springframework.boot.actuate.health.HealthIndicator.class)
    public static class ImportProofHealthConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public ImportProofVerificationHealthIndicator importProofVerificationHealthIndicator(
                CryptoProperties properties,
                ObjectProvider<ImportProofReadiness> readinessProvider) {
            return new ImportProofVerificationHealthIndicator(properties, readinessProvider.getIfAvailable());
        }
    }

    /**
     * 统一 TBOX 设备证书 Profile 能力健康（FW-SEC-DSN-CR-017 §9）：未启用报告 DISABLED，
     * 启用则按 Profile/完整聚合就绪情况报告 NOT_READY/UP，供 VMD keyprov activation 门禁使用。
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(org.springframework.boot.actuate.health.HealthIndicator.class)
    @ConditionalOnProperty(prefix = "crypto.keyprov.certificate-profile", name = "enabled", havingValue = "true")
    public static class KeyprovCertificateProfileHealthConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public KeyprovCertificateProfileHealthIndicator keyprovCertificateProfileHealthIndicator(
                CryptoProperties properties,
                ObjectProvider<KeyprovReadiness> readinessProvider) {
            return new KeyprovCertificateProfileHealthIndicator(properties, readinessProvider.getIfAvailable());
        }
    }

    // ==================== 内部工具 ====================

    private static StepCaProfilePolicyRegistry stepCaProfilePolicyRegistry(CryptoProperties.Pki.StepCa stepCa) {
        Map<String, StepCaProfilePolicy> policies = new LinkedHashMap<>();
        stepCa.getProfiles().forEach((name, p) -> policies.put(name, new StepCaProfilePolicy(
                name,
                p.getProvisioner(),
                p.getKid(),
                p.getJwkSignerRef(),
                p.getMaxValidity(),
                p.getAllowedKeyAlgorithms(),
                p.getRequiredEku(),
                p.getSubjectRule())));
        return new StepCaProfilePolicyRegistry(policies);
    }

    private static boolean isProductionProfile(Environment environment) {
        if (environment == null) {
            return false;
        }
        for (String profile : environment.getActiveProfiles()) {
            String p = profile.toLowerCase();
            if (p.equals("prod") || p.equals("production") || p.contains("prod")) {
                return true;
            }
        }
        return false;
    }
}
