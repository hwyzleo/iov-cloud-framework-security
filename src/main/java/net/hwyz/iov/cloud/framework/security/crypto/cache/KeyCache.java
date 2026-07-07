package net.hwyz.iov.cloud.framework.security.crypto.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.KeyRevokedException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * 密钥缓存
 */
@Component
public class KeyCache {

    private final CryptoProperties properties;
    private final KmsClient kmsClient;

    private Cache<String, CachedDataKey> cache;

    public KeyCache(CryptoProperties properties, KmsClient kmsClient) {
        this.properties = properties;
        this.kmsClient = kmsClient;
    }

    @PostConstruct
    public void init() {
        this.cache = Caffeine.newBuilder()
                .maximumSize(properties.getKeyCache().getMaxSize())
                .expireAfterWrite(properties.getKeyCache().getTtl().toMillis(), TimeUnit.MILLISECONDS)
                .build();
    }

    /**
     * 获取数据密钥（按设备SN和业务类型）
     *
     * @param deviceSn 设备SN
     * @param bizType  业务类型
     * @return 缓存的数据密钥
     */
    public CachedDataKey get(String deviceSn, BizType bizType) {
        String cacheKey = buildCacheKey(deviceSn, bizType);
        CachedDataKey cached = cache.getIfPresent(cacheKey);

        if (cached != null && !cached.getExpireAt().isBefore(Instant.now())) {
            return cached;
        }

        // 缓存未命中或已过期，从KMS获取
        try {
            WrappedKey wrapped = kmsClient.getActiveDataKey(deviceSn, bizType);
            byte[] dekPlaintext = kmsClient.unwrap(wrapped);

            CachedDataKey dataKey = new CachedDataKey();
            dataKey.setKeyId(wrapped.getKeyId());
            dataKey.setKeyVersion(wrapped.getKeyVersion());
            dataKey.setDekPlaintext(dekPlaintext);
            dataKey.setBizType(bizType);
            dataKey.setDeviceSn(deviceSn);
            dataKey.setExpireAt(Instant.now().plus(properties.getKeyCache().getTtl()));

            cache.put(cacheKey, dataKey);
            return dataKey;
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get data key from KMS", e);
        }
    }

    /**
     * 获取数据密钥（按keyId）
     *
     * @param keyId      密钥ID
     * @param keyVersion 密钥版本
     * @return 缓存的数据密钥
     */
    public CachedDataKey get(String keyId, int keyVersion) {
        String cacheKey = buildCacheKey(keyId, keyVersion);
        CachedDataKey cached = cache.getIfPresent(cacheKey);

        if (cached != null && !cached.getExpireAt().isBefore(Instant.now())) {
            return cached;
        }

        // 缓存未命中或已过期，从KMS获取
        try {
            WrappedKey wrapped = kmsClient.getDataKeyById(keyId);
            if (wrapped == null) {
                throw new KeyRevokedException("Key not found or revoked: " + keyId);
            }

            byte[] dekPlaintext = kmsClient.unwrap(wrapped);

            CachedDataKey dataKey = new CachedDataKey();
            dataKey.setKeyId(wrapped.getKeyId());
            dataKey.setKeyVersion(wrapped.getKeyVersion());
            dataKey.setDekPlaintext(dekPlaintext);
            dataKey.setExpireAt(Instant.now().plus(properties.getKeyCache().getTtl()));

            cache.put(cacheKey, dataKey);
            return dataKey;
        } catch (KeyRevokedException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get data key from KMS", e);
        }
    }

    /**
     * 使缓存失效
     *
     * @param keyId 密钥ID
     */
    public void invalidate(String keyId) {
        cache.asMap().entrySet().removeIf(entry -> entry.getValue().getKeyId().equals(keyId));
    }

    private String buildCacheKey(String deviceSn, BizType bizType) {
        return deviceSn + ":" + bizType.name();
    }

    private String buildCacheKey(String keyId, int keyVersion) {
        return keyId + ":" + keyVersion;
    }
}
