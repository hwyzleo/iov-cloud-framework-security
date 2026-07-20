package net.hwyz.iov.cloud.framework.security.crypto.config;

import java.time.Duration;
import java.util.HashMap;
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

        public Retry getRetry() {
            return retry;
        }

        public void setRetry(Retry retry) {
            this.retry = retry;
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
