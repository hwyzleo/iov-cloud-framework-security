package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.CertEncryptionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.CertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.CryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DataKeyDistributionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCertEncryptionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultDataKeyDistributionTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultKeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultSigningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.KeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.SigningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.client.DefaultKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.DefaultPkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.FeignKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsFeignClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.LegacyRestPkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiFeignClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateChainValidator;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.EnrollmentIdempotencyService;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.HttpStepCaApiClient;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.InMemoryCertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.JwkStepCaTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.RedisCertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaApiClient;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaPkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaProfilePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaProfilePolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaTokenProvider;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultCertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultDeviceResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
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

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.kms", name = "endpoint")
    public KmsClient kmsClient(CryptoProperties properties, KmsFeignClient kmsFeignClient) {
        return new FeignKmsClient(properties, kmsFeignClient);
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
                                         CryptoMetrics cryptoMetrics, KmsClient kmsClient) {
        return new DefaultCryptoTemplate(deviceResolver, keyCache, aeadCipher, envelopeCodec,
                cryptoMetrics, kmsClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.provisioning", name = "enabled", havingValue = "true")
    public KeyProvisioningTemplate keyProvisioningTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics,
                                                           CryptoProperties properties,
                                                           ObjectProvider<DeviceResolver> deviceResolverProvider) {
        return new DefaultKeyProvisioningTemplate(kmsClient, cryptoMetrics, properties,
                deviceResolverProvider.getIfAvailable());
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
    public CertResolver certResolver() {
        return new DefaultCertResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.pki", name = "endpoint")
    public CertEncryptionTemplate certEncryptionTemplate(CryptoMetrics cryptoMetrics,
                                                           ObjectProvider<CertResolver> certResolverProvider) {
        return new DefaultCertEncryptionTemplate(cryptoMetrics, certResolverProvider.getIfAvailable());
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
                                     Environment environment) {
        CryptoProperties.Pki pki = properties.getPki();
        CryptoProperties.Pki.StepCa stepCa = pki.getStepCa();

        // 启动校验
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

        // step-ca API 客户端（启动即建立根指纹固定信任锚）
        StepCaApiClient apiClient = new HttpStepCaApiClient(
                endpoint, stepCa.getRootSha256(),
                pki.getConnectTimeout(), pki.getReadTimeout(),
                pki.getRetry().getMaxAttempts(), pki.getRetry().getBaseBackoff());

        StepCaTokenProvider tokenProvider = stepCaTokenProvider(stepCa);
        StepCaProfilePolicyRegistry registry = stepCaProfilePolicyRegistry(stepCa);

        PkiClient client = new StepCaPkiClient(
                apiClient, tokenProvider, registry, resultStore, chainValidator,
                idempotencyService, cryptoMetrics, endpoint, stepCa.getRootSha256());

        log.info("step-ca 证书注册装配完成: provider=step-ca, endpoint={}, rootFingerprint=...{}, "
                        + "resultStore={}, profiles={}",
                endpoint.getHost(),
                stepCa.getRootSha256().replace(":", "").substring(
                        Math.max(0, stepCa.getRootSha256().replace(":", "").length() - 8)),
                resultStore.getClass().getSimpleName(), registry.profileNames());
        return client;
    }

    /**
     * legacy-rest 提供方：默认（未配置 provider 时保持存量行为）。
     */
    @Bean
    @ConditionalOnMissingBean(PkiClient.class)
    @ConditionalOnProperty(prefix = "crypto.pki", name = "endpoint")
    @ConditionalOnExpression("'${crypto.pki.provider:legacy-rest}' == 'legacy-rest'")
    public PkiClient legacyRestPkiClient(CryptoProperties properties, PkiFeignClient pkiFeignClient) {
        CryptoProperties.Pki pki = properties.getPki();
        log.info("legacy-rest 证书注册装配完成: endpoint={}", pki.getEndpoint());
        return new LegacyRestPkiClient(properties, pkiFeignClient);
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

    // ==================== 内部工具 ====================

    private static StepCaTokenProvider stepCaTokenProvider(CryptoProperties.Pki.StepCa stepCa) {
        if (!"jwk".equalsIgnoreCase(stepCa.getTokenProvider())) {
            throw new IllegalStateException("Unsupported step-ca token-provider: " + stepCa.getTokenProvider()
                    + " (only 'jwk' is currently supported)");
        }
        Path privateKeyFile = Path.of(stepCa.getJwk().getPrivateKeyFile());
        if (!Files.isReadable(privateKeyFile)) {
            throw new IllegalStateException(
                    "step-ca JWK private key file is not readable: " + privateKeyFile
                            + " (must be mounted read-only Secret)");
        }
        Path passwordFile = stepCa.getJwk().getPasswordFile() != null
                ? Path.of(stepCa.getJwk().getPasswordFile()) : null;
        if (passwordFile != null && !Files.isReadable(passwordFile)) {
            throw new IllegalStateException("step-ca JWK password file is not readable: " + passwordFile);
        }
        return new JwkStepCaTokenProvider(privateKeyFile, passwordFile, stepCa.getTokenTtl());
    }

    private static StepCaProfilePolicyRegistry stepCaProfilePolicyRegistry(CryptoProperties.Pki.StepCa stepCa) {
        Map<String, StepCaProfilePolicy> policies = new LinkedHashMap<>();
        stepCa.getProfiles().forEach((name, p) -> policies.put(name, new StepCaProfilePolicy(
                name,
                p.getProvisioner(),
                p.getKid(),
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
