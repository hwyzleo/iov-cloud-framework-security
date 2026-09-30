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
         * 重试次数
         */
        private int retryCount = 2;

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

        public int getRetryCount() {
            return retryCount;
        }

        public void setRetryCount(int retryCount) {
            this.retryCount = retryCount;
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
         * 是否启用 DataKeyDistributionTemplate 门面装配
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
             * 只读私钥文件路径（明文 JWK 或 step-ca 口令加密 JWK）
             */
            private String privateKeyFile;

            /**
             * 解密口令文件路径（仅加密 JWK 需要；独立 Secret 注入）
             */
            private String passwordFile;

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
