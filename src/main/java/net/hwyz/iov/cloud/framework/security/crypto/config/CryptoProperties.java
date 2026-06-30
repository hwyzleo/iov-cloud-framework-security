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
     * 业务域→器件类别路由表
     */
    private Map<String, String> deviceRouting = new HashMap<>();

    /**
     * 失败策略（CLOSED/OPEN）
     */
    private String failMode = "CLOSED";

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

    public Map<String, String> getDeviceRouting() {
        return deviceRouting;
    }

    public void setDeviceRouting(Map<String, String> deviceRouting) {
        this.deviceRouting = deviceRouting;
    }

    public String getFailMode() {
        return failMode;
    }

    public void setFailMode(String failMode) {
        this.failMode = failMode;
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
}
