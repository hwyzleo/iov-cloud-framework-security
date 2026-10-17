package net.hwyz.iov.cloud.framework.security.crypto.config;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Configuration;

/**
 * 加解密配置属性
 */
@Configuration
@RefreshScope
@ConfigurationProperties(prefix = "crypto")
public class CryptoProperties {

    /**
     * KMS配置
     */
    private Kms kms = new Kms();

    /**
     * 密钥缓存配置
     */
    private KeyCache keyCache = new KeyCache();

    /**
     * 绑定缓存配置
     */
    private BindingCache bindingCache = new BindingCache();

    /**
     * AEAD算法
     */
    private String alg = "AES_256_GCM";

    /**
     * 失败策略（CLOSED/OPEN）
     */
    private String failMode = "CLOSED";

    /**
     * 信封加解密是否启用
     */
    private boolean envelopeEnabled = true;

    /**
     * 密钥派生/封装下发配置
     */
    private Provisioning provisioning = new Provisioning();

    /**
     * 数据密钥下发门面配置（CR-005）
     */
    private KeyProv keyProv = new KeyProv();

    /**
     * 运行期业务密钥材料与目录配置（FW-SEC-DSN-CR-009）
     */
    private BusinessKey businessKey = new BusinessKey();

    /**
     * 非对称签名/验签门面配置（CR-006）
     */
    private Signing signing = new Signing();

    /**
     * PKI 证书注册门面配置（CR-007）
     */
    private Pki pki = new Pki();

    public Kms getKms() {
        return kms;
    }

    public void setKms(Kms kms) {
        this.kms = kms;
    }

    public KeyCache getKeyCache() {
        return keyCache;
    }

    public void setKeyCache(KeyCache keyCache) {
        this.keyCache = keyCache;
    }

    public BindingCache getBindingCache() {
        return bindingCache;
    }

    public void setBindingCache(BindingCache bindingCache) {
        this.bindingCache = bindingCache;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getFailMode() {
        return failMode;
    }

    public void setFailMode(String failMode) {
        this.failMode = failMode;
    }

    public boolean isEnvelopeEnabled() {
        return envelopeEnabled;
    }

    public void setEnvelopeEnabled(boolean envelopeEnabled) {
        this.envelopeEnabled = envelopeEnabled;
    }

    public Provisioning getProvisioning() {
        return provisioning;
    }

    public void setProvisioning(Provisioning provisioning) {
        this.provisioning = provisioning;
    }

    public KeyProv getKeyProv() {
        return keyProv;
    }

    public void setKeyProv(KeyProv keyProv) {
        this.keyProv = keyProv;
    }

    public BusinessKey getBusinessKey() {
        return businessKey;
    }

    public void setBusinessKey(BusinessKey businessKey) {
        this.businessKey = businessKey;
    }

    public Signing getSigning() {
        return signing;
    }

    public void setSigning(Signing signing) {
        this.signing = signing;
    }

    public Pki getPki() {
        return pki;
    }

    public void setPki(Pki pki) {
        this.pki = pki;
    }

    /**
     * KMS配置
     */
    public static class Kms {
        /**
         * KMS服务地址
         */
        private String endpoint;

        /**
         * Provider 身份（FW-SEC-DSN-CR-011 §7）。
         * <p>
         * 契约期望值，仅用于启动时与 capability 响应校验；不参与运行时 URL 拼接。
         */
        private String provider = "openbao-business-key";

        /**
         * 鉴权方式（approle；凭据经 Secret 注入，不写入普通配置明文）
         */
        private String auth = "approle";

        /**
         * OpenBao/Vault访问令牌
         */
        private String token;

        /**
         * 连接超时
         */
        private Duration connectTimeout = Duration.ofMillis(500);

        /**
         * 读超时
         */
        private Duration readTimeout = Duration.ofSeconds(1);

        /**
         * 总预算（连接、读取与有限重试共享）
         */
        private Duration totalTimeout = Duration.ofSeconds(2);

        /**
         * 重试次数
         */
        private int retryCount = 2;

        /**
         * 运行期业务密钥 Provider 适配配置（FW-SEC-DSN-CR-011 §7）。
         * <p>
         * mount/api-version/capability-path 为契约期望值，仅用于启动校验，
         * 不参与运行时 URL 拼接或重写；任一不匹配即 fail-closed。
         */
        private BusinessKey businessKey = new BusinessKey();

        public String getEndpoint() {
            return endpoint;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getAuth() {
            return auth;
        }

        public void setAuth(String auth) {
            this.auth = auth;
        }

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }

        public Duration getConnectTimeout() {
            return connectTimeout;
        }

        public void setConnectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
        }

        public Duration getReadTimeout() {
            return readTimeout;
        }

        public void setReadTimeout(Duration readTimeout) {
            this.readTimeout = readTimeout;
        }

        public Duration getTotalTimeout() {
            return totalTimeout;
        }

        public void setTotalTimeout(Duration totalTimeout) {
            this.totalTimeout = totalTimeout;
        }

        public int getRetryCount() {
            return retryCount;
        }

        public void setRetryCount(int retryCount) {
            this.retryCount = retryCount;
        }

        public BusinessKey getBusinessKey() {
            return businessKey;
        }

        public void setBusinessKey(BusinessKey businessKey) {
            this.businessKey = businessKey;
        }

        /**
         * 运行期业务密钥 Provider 适配配置（crypto.kms.business-key.*）。
         * <p>
         * 只控制 Provider 适配；公共门面仍由 {@code crypto.business-key.enabled} 控制。
         */
        public static class BusinessKey {
            /**
             * 是否启用 Provider 适配（能力探测/启动门禁/Health）
             */
            private boolean enabled = false;

            /**
             * mount 契约期望值（启动校验，不参与 URL 拼接）
             */
            private String mount = "business-key";

            /**
             * API 版本契约期望值（启动校验，不参与 URL 拼接）
             */
            private String apiVersion = "v1";

            /**
             * capability 路径契约期望值（启动校验；wire 路径固定为 /v1/business-key/capabilities）
             */
            private String capabilityPath = "/v1/business-key/capabilities";

            /**
             * 启动时是否要求 capability READY；未 READY 则启动 fail-closed
             */
            private boolean requireReadyAtStartup = true;

            /**
             * 是否启用对账语义（operationId/幂等键）
             */
            private boolean reconcileEnabled = true;

            public boolean isEnabled() {
                return enabled;
            }

            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }

            public String getMount() {
                return mount;
            }

            public void setMount(String mount) {
                this.mount = mount;
            }

            public String getApiVersion() {
                return apiVersion;
            }

            public void setApiVersion(String apiVersion) {
                this.apiVersion = apiVersion;
            }

            public String getCapabilityPath() {
                return capabilityPath;
            }

            public void setCapabilityPath(String capabilityPath) {
                this.capabilityPath = capabilityPath;
            }

            public boolean isRequireReadyAtStartup() {
                return requireReadyAtStartup;
            }

            public void setRequireReadyAtStartup(boolean requireReadyAtStartup) {
                this.requireReadyAtStartup = requireReadyAtStartup;
            }

            public boolean isReconcileEnabled() {
                return reconcileEnabled;
            }

            public void setReconcileEnabled(boolean reconcileEnabled) {
                this.reconcileEnabled = reconcileEnabled;
            }
        }
    }

    /**
     * 密钥缓存配置
     */
    public static class KeyCache {
        /**
         * DEK本地缓存TTL
         */
        private Duration ttl = Duration.ofMinutes(10);

        /**
         * 缓存最大条目
         */
        private int maxSize = 10000;

        public Duration getTtl() {
            return ttl;
        }

        public void setTtl(Duration ttl) {
            this.ttl = ttl;
        }

        public int getMaxSize() {
            return maxSize;
        }

        public void setMaxSize(int maxSize) {
            this.maxSize = maxSize;
        }
    }

    /**
     * 绑定缓存配置
     */
    public static class BindingCache {
        /**
         * 绑定解析缓存TTL
         */
        private Duration ttl = Duration.ofMinutes(5);

        public Duration getTtl() {
            return ttl;
        }

        public void setTtl(Duration ttl) {
            this.ttl = ttl;
        }
    }

    /**
     * 密钥派生/封装下发配置
     */
    public static class Provisioning {
        /**
         * 是否启用派生/封装门面装配
         */
        private boolean enabled = false;

        /**
         * KMS提供方（写入 ProvisioningResult.provider）
         */
        private String provider = "Vault-Transit";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }
    }

    /**
     * 数据密钥下发门面配置（CR-005）
     */
    public static class KeyProv {
        /**
         * 是否启用 DataKeyDistributionTemplate 门面装配（CR-005；FW-SEC-DSN-CR-009 起仅作 deprecated 兼容开关，
         * 新代码使用 crypto.business-key.enabled）
         */
        private boolean enabled = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * 运行期业务密钥材料与目录配置（FW-SEC-DSN-CR-009 §10）
     */
    public static class BusinessKey {
        /**
         * 是否装配 BusinessKeyMaterialTemplate 材料门面（纯 VMD 编排开启）
         */
        private boolean enabled = false;

        /**
         * 运行期封装（RUNTIME）解封所用的 KMS 命名密钥引用（运行时边界包裹密钥）
         */
        private String runtimeKeyName = "runtime";

        /**
         * 业务目录 Resolver Adapter 配置（业务加解密服务开启）
         */
        private Directory directory = new Directory();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getRuntimeKeyName() {
            return runtimeKeyName;
        }

        public void setRuntimeKeyName(String runtimeKeyName) {
            this.runtimeKeyName = runtimeKeyName;
        }

        public Directory getDirectory() {
            return directory;
        }

        public void setDirectory(Directory directory) {
            this.directory = directory;
        }

        /**
         * 业务目录 Resolver Adapter 配置
         */
        public static class Directory {
            /**
             * 是否装配 BusinessKeyDirectoryResolver（Resolver Adapter；由消费服务接入 VMD Service API）
             */
            private boolean enabled = false;

            public boolean isEnabled() {
                return enabled;
            }

            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
        }
    }

    /**
     * 非对称签名/验签门面配置（CR-006）
     */
    public static class Signing {
        /**
         * 是否启用 SigningTemplate 门面装配
         */
        private boolean enabled = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * PKI 证书注册门面配置（CR-007）
     */
    public static class Pki {
        /**
         * PKI 服务端点
         */
        private String endpoint;

        /**
         * PKI 访问令牌
         */
        private String token;

        /**
         * PKI 提供方（legacy-rest | step-ca，FW-SEC-DSN-CR-008 §2.1）。
         * 未配置时保持 legacy-rest 行为。
         */
        private String provider;

        /**
         * 证书注册门面装配开关
         */
        private Enrollment enrollment = new Enrollment();

        /**
         * step-ca 原生适配配置（provider=step-ca 时生效，FW-SEC-DSN-CR-008 §2/§4/§7）
         */
        private StepCa stepCa = new StepCa();

        /**
         * 连接超时
         */
        private Duration connectTimeout = Duration.ofMillis(500);

        /**
         * 读超时
         */
        private Duration readTimeout = Duration.ofSeconds(2);

        /**
         * 重试配置
         */
        private Retry retry = new Retry();

        /**
         * PKI HTTPS 传输层信任配置（legacy-rest provider 的 Feign 客户端使用）。
         * <p>
         * 配置后，PKI Feign 客户端仅信任此处提供的根/CA 证书（受控 truststore，禁 trust-all），
         * 不再依赖 JVM 全局 cacerts；未配置时退回 JDK 默认信任（行为不变）。
         */
        private Tls tls = new Tls();

        /**
         * 证书材料解析配置（FW-SEC-DSN-CR-012 §8）。
         */
        private CertificateResolution certificateResolution = new CertificateResolution();

        public String getEndpoint() {
            return endpoint;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public Enrollment getEnrollment() {
            return enrollment;
        }

        public void setEnrollment(Enrollment enrollment) {
            this.enrollment = enrollment;
        }

        public StepCa getStepCa() {
            return stepCa;
        }

        public void setStepCa(StepCa stepCa) {
            this.stepCa = stepCa;
        }

        public Duration getConnectTimeout() {
            return connectTimeout;
        }

        public void setConnectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
        }

        public Duration getReadTimeout() {
            return readTimeout;
        }

        public void setReadTimeout(Duration readTimeout) {
            this.readTimeout = readTimeout;
        }

        public Retry getRetry() {
            return retry;
        }

        public void setRetry(Retry retry) {
            this.retry = retry;
        }

        public Tls getTls() {
            return tls;
        }

        public void setTls(Tls tls) {
            this.tls = tls;
        }

        public CertificateResolution getCertificateResolution() {
            return certificateResolution;
        }

        public void setCertificateResolution(CertificateResolution certificateResolution) {
            this.certificateResolution = certificateResolution;
        }

        /**
         * PKI HTTPS 传输层信任配置。
         * <p>
         * 两种来源（同时配置时以 {@code trustStoreFile} 优先）：
         * <ul>
         *   <li>{@code trustedCertsPem}：内联 PEM（可含多张证书的 bundle），适合配置中心下发，
         *       无需 keytool、无需挂载文件；</li>
         *   <li>{@code trustStoreFile}：JKS/PKCS12 truststore 文件路径（配合口令与类型）。</li>
         * </ul>
         * 均未配置时退回 JDK 默认信任（行为不变）。
         */
        public static class Tls {
            /**
             * 受信根/CA 证书 PEM（可含多张，PEM bundle）。
             */
            private String trustedCertsPem;

            /**
             * truststore 文件路径（JKS/PKCS12）。
             */
            private String trustStoreFile;

            /**
             * truststore 口令。
             */
            private String trustStorePassword;

            /**
             * truststore 类型（JKS / PKCS12），默认 PKCS12。
             */
            private String trustStoreType = "PKCS12";

            public String getTrustedCertsPem() {
                return trustedCertsPem;
            }

            public void setTrustedCertsPem(String trustedCertsPem) {
                this.trustedCertsPem = trustedCertsPem;
            }

            public String getTrustStoreFile() {
                return trustStoreFile;
            }

            public void setTrustStoreFile(String trustStoreFile) {
                this.trustStoreFile = trustStoreFile;
            }

            public String getTrustStorePassword() {
                return trustStorePassword;
            }

            public void setTrustStorePassword(String trustStorePassword) {
                this.trustStorePassword = trustStorePassword;
            }

            public String getTrustStoreType() {
                return trustStoreType;
            }

            public void setTrustStoreType(String trustStoreType) {
                this.trustStoreType = trustStoreType == null || trustStoreType.isBlank()
                        ? "PKCS12" : trustStoreType;
            }

            /**
             * 是否配置了任一信任来源。
             */
            public boolean isConfigured() {
                return (trustedCertsPem != null && !trustedCertsPem.isBlank())
                        || (trustStoreFile != null && !trustStoreFile.isBlank());
            }
        }

        /**
         * 证书注册门面装配开关
         */
        public static class Enrollment {
            /**
             * 是否装配 CertEnrollmentTemplate（默认 true，仍要求配置 crypto.pki.endpoint）
             */
            private boolean enabled = true;

            public boolean isEnabled() {
                return enabled;
            }

            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
        }

        /**
         * step-ca 原生适配配置（provider=step-ca 时生效，FW-SEC-DSN-CR-008 §2/§4/§7）
         */
        public static class StepCa {
            /**
             * 根证书 SHA-256 指纹（固定信任锚，必填）
             */
            private String rootSha256;

            /**
             * OTT 提供者类型（当前仅 jwk）
             */
            private String tokenProvider = "jwk";

            /**
             * OTT 默认有效期（默认 5 分钟且可缩短）
             */
            private Duration tokenTtl = Duration.ofMinutes(5);

            /**
             * 结果存储 TTL（不短于业务补偿窗口）
             */
            private Duration storeTtl = Duration.ofDays(30);

            /**
             * JWK 私钥来源配置
             */
            private Jwk jwk = new Jwk();

            /**
             * profile → step-ca 策略映射（仅 framework 治理的 CertificateProfile）
             */
            private Map<String, ProfilePolicy> profiles = new java.util.LinkedHashMap<>();

            public String getRootSha256() {
                return rootSha256;
            }

            public void setRootSha256(String rootSha256) {
                this.rootSha256 = rootSha256;
            }

            public String getTokenProvider() {
                return tokenProvider;
            }

            public void setTokenProvider(String tokenProvider) {
                this.tokenProvider = tokenProvider;
            }

            public Duration getTokenTtl() {
                return tokenTtl;
            }

            public void setTokenTtl(Duration tokenTtl) {
                this.tokenTtl = tokenTtl;
            }

            public Duration getStoreTtl() {
                return storeTtl;
            }

            public void setStoreTtl(Duration storeTtl) {
                this.storeTtl = storeTtl;
            }

            public Jwk getJwk() {
                return jwk;
            }

            public void setJwk(Jwk jwk) {
                this.jwk = jwk;
            }

            public Map<String, ProfilePolicy> getProfiles() {
                return profiles;
            }

            public void setProfiles(Map<String, ProfilePolicy> profiles) {
                this.profiles = profiles;
            }
        }

        /**
         * JWK 私钥来源配置
         */
        public static class Jwk {
            /**
             * 只读私钥文件路径（明文 JWK 或 step-ca 口令加密 JWK）。
             * <p>
             * 与 {@code privateKeyContent} 二选一；同时配置时以 {@code privateKeyContent} 优先。
             */
            private String privateKeyFile;

            /**
             * 解密口令文件路径（仅加密 JWK 需要；独立 Secret 注入）。
             */
            private String passwordFile;

            /**
             * 内联 JWK 内容（明文 JWK 或 step-ca 口令加密 JWK 的 JSON），适合配置中心/Nacos 下发。
             * <p>
             * 推荐使用 step-ca 口令加密 JWK（含 {@code encryptedKey}）：密文可安全入 Nacos，
             * 配一次全服务共享，无需逐个容器挂载文件。
             */
            private String privateKeyContent;

            /**
             * 解密口令（仅加密 JWK 需要）。
             * <p>
             * 属于敏感材料：建议以环境变量占位符注入（如 {@code ${STEPCA_PROVISIONER_PASSWORD}}），
             * 不要在 Nacos 明文保存。
             */
            private String password;

            public String getPrivateKeyFile() {
                return privateKeyFile;
            }

            public void setPrivateKeyFile(String privateKeyFile) {
                this.privateKeyFile = privateKeyFile;
            }

            public String getPasswordFile() {
                return passwordFile;
            }

            public void setPasswordFile(String passwordFile) {
                this.passwordFile = passwordFile;
            }

            public String getPrivateKeyContent() {
                return privateKeyContent;
            }

            public void setPrivateKeyContent(String privateKeyContent) {
                this.privateKeyContent = privateKeyContent;
            }

            public String getPassword() {
                return password;
            }

            public void setPassword(String password) {
                this.password = password;
            }

            /**
             * 是否配置了内联 JWK 内容。
             */
            public boolean hasInlineContent() {
                return privateKeyContent != null && !privateKeyContent.isBlank();
            }
        }

        /**
         * profile → step-ca 策略
         */
        public static class ProfilePolicy {
            /**
             * step-ca provisioner 名
             */
            private String provisioner;

            /**
             * provisioner JWK 的 kid
             */
            private String kid;

            /**
             * 最大签发有效期
             */
            private Duration maxValidity;

            /**
             * 允许的密钥算法（如 EC_P256）
             */
            private List<String> allowedKeyAlgorithms = java.util.List.of();

            /**
             * 要求的扩展密钥用法（如 CLIENT_AUTH）
             */
            private List<String> requiredEku = java.util.List.of();

            /**
             * 主体规则（subject/SAN 前缀约束）
             */
            private String subjectRule;

            public String getProvisioner() {
                return provisioner;
            }

            public void setProvisioner(String provisioner) {
                this.provisioner = provisioner;
            }

            public String getKid() {
                return kid;
            }

            public void setKid(String kid) {
                this.kid = kid;
            }

            public Duration getMaxValidity() {
                return maxValidity;
            }

            public void setMaxValidity(Duration maxValidity) {
                this.maxValidity = maxValidity;
            }

            public List<String> getAllowedKeyAlgorithms() {
                return allowedKeyAlgorithms;
            }

            public void setAllowedKeyAlgorithms(List<String> allowedKeyAlgorithms) {
                this.allowedKeyAlgorithms = allowedKeyAlgorithms == null
                        ? java.util.List.of() : allowedKeyAlgorithms;
            }

            public List<String> getRequiredEku() {
                return requiredEku;
            }

            public void setRequiredEku(List<String> requiredEku) {
                this.requiredEku = requiredEku == null ? java.util.List.of() : requiredEku;
            }

            public String getSubjectRule() {
                return subjectRule;
            }

            public void setSubjectRule(String subjectRule) {
                this.subjectRule = subjectRule;
            }
        }

        /**
         * 证书材料解析配置（FW-SEC-DSN-CR-012 §8）。
         * <p>
         * 前缀 {@code crypto.pki.certificate-resolution}。默认关闭，避免升级 framework 后改变既有行为。
         * 信任锚必须显式配置 {@code trust-anchors-pem}，不接受从 TLS 传输信任或吊销查询 issuer 隐式回退。
         */
        public static class CertificateResolution {
            /**
             * 是否启用 framework 默认证书解析编排
             */
            private boolean enabled = false;

            /**
             * 是否优先使用调用方携带的 inline DER/SPKI
             */
            private boolean inlineFirst = true;

            /**
             * 是否允许按 Provider serial 查询（仅 capability 支持时真正生效）
             */
            private boolean providerQueryEnabled = true;

            /**
             * 是否允许领域目录 locator
             */
            private boolean domainDirectoryEnabled = true;

            /**
             * 多个目录命中不同 locator 时是否必须唯一（true 则拒绝）
             */
            private boolean requireUniqueResult = true;

            /**
             * 业务证书签发信任锚 PEM（可含多张）。启用解析能力且要求受信链时必须显式配置。
             */
            private String trustAnchorsPem;

            /**
             * 业务密钥封装场景策略
             */
            private BusinessKeyWrap businessKeyWrap = new BusinessKeyWrap();

            public boolean isEnabled() {
                return enabled;
            }

            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }

            public boolean isInlineFirst() {
                return inlineFirst;
            }

            public void setInlineFirst(boolean inlineFirst) {
                this.inlineFirst = inlineFirst;
            }

            public boolean isProviderQueryEnabled() {
                return providerQueryEnabled;
            }

            public void setProviderQueryEnabled(boolean providerQueryEnabled) {
                this.providerQueryEnabled = providerQueryEnabled;
            }

            public boolean isDomainDirectoryEnabled() {
                return domainDirectoryEnabled;
            }

            public void setDomainDirectoryEnabled(boolean domainDirectoryEnabled) {
                this.domainDirectoryEnabled = domainDirectoryEnabled;
            }

            public boolean isRequireUniqueResult() {
                return requireUniqueResult;
            }

            public void setRequireUniqueResult(boolean requireUniqueResult) {
                this.requireUniqueResult = requireUniqueResult;
            }

            public String getTrustAnchorsPem() {
                return trustAnchorsPem;
            }

            public void setTrustAnchorsPem(String trustAnchorsPem) {
                this.trustAnchorsPem = trustAnchorsPem;
            }

            public BusinessKeyWrap getBusinessKeyWrap() {
                return businessKeyWrap;
            }

            public void setBusinessKeyWrap(BusinessKeyWrap businessKeyWrap) {
                this.businessKeyWrap = businessKeyWrap;
            }
        }

        /**
         * 业务密钥 DEVICE_CERT_PUBLIC_KEY 封装场景证书解析策略。
         */
        public static class BusinessKeyWrap {
            /**
             * 是否必须取得叶子证书 DER
             */
            private boolean requireCertificate = true;

            /**
             * 是否要求证书链可验证到配置信任锚
             */
            private boolean requireTrustedChain = true;

            /**
             * 是否要求吊销状态为 GOOD（UNKNOWN 视为不可用）。
             * 为 true 时必须同时启用 {@code crypto.pki.revocation.enabled}；dev/test 可显式关闭。
             */
            private boolean requireGoodStatus = true;

            public boolean isRequireCertificate() {
                return requireCertificate;
            }

            public void setRequireCertificate(boolean requireCertificate) {
                this.requireCertificate = requireCertificate;
            }

            public boolean isRequireTrustedChain() {
                return requireTrustedChain;
            }

            public void setRequireTrustedChain(boolean requireTrustedChain) {
                this.requireTrustedChain = requireTrustedChain;
            }

            public boolean isRequireGoodStatus() {
                return requireGoodStatus;
            }

            public void setRequireGoodStatus(boolean requireGoodStatus) {
                this.requireGoodStatus = requireGoodStatus;
            }
        }

        /**
         * 重试配置
         */
        public static class Retry {
            /**
             * 最大重试次数
             */
            private int maxAttempts = 2;

            /**
             * 基础退避时间
             */
            private Duration baseBackoff = Duration.ofMillis(100);

            public int getMaxAttempts() {
                return maxAttempts;
            }

            public void setMaxAttempts(int maxAttempts) {
                this.maxAttempts = maxAttempts;
            }

            public Duration getBaseBackoff() {
                return baseBackoff;
            }

            public void setBaseBackoff(Duration baseBackoff) {
                this.baseBackoff = baseBackoff;
            }
        }
    }
}
