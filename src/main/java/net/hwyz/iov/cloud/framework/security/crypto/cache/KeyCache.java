package net.hwyz.iov.cloud.framework.security.crypto.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyCacheInvalidator;
import net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyMaterialTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyDirectoryUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.KeyRevokedException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyDescriptor;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrappedBusinessKey;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * 密钥缓存（FW-SEC-DSN-CR-009 §8）。
 * <p>
 * 新寻址路径（ENVELOPE 正反向）：按 {@link BusinessKeyDescriptor} 的显式 keyRef 取钥，
 * 缓存未命中时经 {@link BusinessKeyMaterialTemplate#wrap}（RUNTIME）获取 Wrapped Key 并在
 * 受控运行期边界解封，TTL 缓存；缓存失效由 {@link BusinessKeyCacheInvalidator} 主动触发，
 * TTL 仅作故障兜底。Wrapped Key 不落库、不进日志或事件。
 */
@Component
public class KeyCache implements BusinessKeyCacheInvalidator {

    private final CryptoProperties properties;
    private final KmsClient kmsClient;
    private final String runtimeKeyName;

    private Cache<String, CachedDataKey> cache;

    public KeyCache(CryptoProperties properties, KmsClient kmsClient) {
        this.properties = properties;
        this.kmsClient = kmsClient;
        this.runtimeKeyName = properties.getBusinessKey().getRuntimeKeyName();
    }

    @PostConstruct
    public void init() {
        this.cache = Caffeine.newBuilder()
                .maximumSize(properties.getKeyCache().getMaxSize())
                .expireAfterWrite(properties.getKeyCache().getTtl().toMillis(), TimeUnit.MILLISECONDS)
                .build();
    }

    /**
     * 获取业务数据密钥（FW-SEC-DSN-CR-009 §5 新寻址路径）。
     * <p>
     * 缓存键为 (keyId, businessKeyVersion)；未命中时按目录返回的显式 {@code kmsKeyRef}
     * 经材料门面 RUNTIME 封装取钥并解封。目录/材料门面未装配时 fail-closed，不得直连 KMS 降级。
     *
     * @param descriptor       目录返回的唯一业务密钥描述（已通过 Resolver 授权）
     * @param deviceSn         设备 SN（缓存上下文，可为 null）
     * @param bizType          业务类型（缓存上下文，可为 null）
     * @param purpose          业务用途（缓存上下文，可为 null）
     * @param materialTemplate 材料门面（RUNTIME 取钥；null 时 fail-closed）
     * @return 缓存的数据密钥
     */
    public CachedDataKey get(BusinessKeyDescriptor descriptor, String deviceSn, BizType bizType,
                             String purpose, BusinessKeyMaterialTemplate materialTemplate) {
        Objects.requireNonNull(descriptor, "descriptor must not be null");
        if (materialTemplate == null) {
            throw new BusinessKeyDirectoryUnavailableException(
                    "BusinessKeyMaterialTemplate 未装配（crypto.business-key.enabled=false），"
                            + "无法按显式 keyRef 取业务密钥材料（FW-SEC-DSN-CR-009 §5）");
        }
        String cacheKey = buildCacheKey(descriptor.keyId(), descriptor.businessKeyVersion());
        CachedDataKey cached = cache.getIfPresent(cacheKey);

        if (cached != null && !cached.getExpireAt().isBefore(Instant.now())) {
            return cached;
        }

        try {
            WrappedBusinessKey wrapped = materialTemplate.wrap(
                    new BusinessKeyRef(descriptor.keyId(), descriptor.kmsKeyRef()),
                    new RecipientRef.RuntimeIdentity(runtimeKeyName),
                    new WrapContext(WrapMode.RUNTIME, null, null));
            byte[] dekPlaintext = kmsClient.unwrap(runtimeKeyName, toWrappedKey(wrapped));

            CachedDataKey dataKey = new CachedDataKey();
            dataKey.setKeyId(descriptor.keyId());
            dataKey.setKeyVersion(businessKeyVersionAsInt(descriptor.businessKeyVersion()));
            dataKey.setDekPlaintext(dekPlaintext);
            dataKey.setBizType(bizType);
            dataKey.setDeviceSn(deviceSn);
            dataKey.setPurpose(purpose);
            dataKey.setExpireAt(Instant.now().plus(properties.getKeyCache().getTtl()));

            cache.put(cacheKey, dataKey);
            return dataKey;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException(
                    "Failed to load business key material (keyId=" + descriptor.keyId() + ")", e);
        }
    }

    /**
     * 获取数据密钥（按设备SN和业务类型）
     *
     * @param deviceSn 设备SN
     * @param bizType  业务类型
     * @return 缓存的数据密钥
     * @deprecated 由 FW-SEC-DSN-CR-009 取代：framework 不再按 deviceSn+BizType 直接选活跃 key，
     * 请经 {@link net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyDirectoryResolver} 寻址。
     */
    @Deprecated
    public CachedDataKey get(String deviceSn, BizType bizType) {
        String cacheKey = buildCacheKey(deviceSn, bizType);
        CachedDataKey cached = cache.getIfPresent(cacheKey);

        if (cached != null && !cached.getExpireAt().isBefore(Instant.now())) {
            return cached;
        }

        // 缓存未命中或已过期，从KMS获取
        try {
            String keyName = bizType.prov() != null ? bizType.prov().keyName() : "default";
            WrappedKey wrapped = kmsClient.getActiveDataKey(keyName, bizType);
            byte[] dekPlaintext = kmsClient.unwrap(keyName, wrapped);

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
     * @deprecated 由 FW-SEC-DSN-CR-009 取代：反向寻址必须先经
     * {@link net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyDirectoryResolver} 授权。
     */
    @Deprecated
    public CachedDataKey get(String keyId, int keyVersion) {
        String cacheKey = buildCacheKey(keyId, keyVersion);
        CachedDataKey cached = cache.getIfPresent(cacheKey);

        if (cached != null && !cached.getExpireAt().isBefore(Instant.now())) {
            return cached;
        }

        // 缓存未命中或已过期，从KMS获取
        try {
            WrappedKey wrapped = kmsClient.getDataKeyById(keyId, keyId);
            if (wrapped == null) {
                throw new KeyRevokedException("Key not found or revoked: " + keyId);
            }

            byte[] dekPlaintext = kmsClient.unwrap(keyId, wrapped);

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
     * 按 keyId 失效缓存（FW-SEC-DSN-CR-009 §8）。
     *
     * @param keyId 密钥ID
     */
    @Override
    public void invalidateKey(String keyId) {
        cache.asMap().entrySet().removeIf(entry -> entry.getValue().getKeyId().equals(keyId));
    }

    /**
     * 按设备维业务上下文失效缓存（FW-SEC-DSN-CR-009 §8）。
     *
     * @param deviceSn 设备 SN
     * @param bizType  业务类型
     * @param purpose  业务用途（null 表示任意用途）
     */
    @Override
    public void invalidateContext(String deviceSn, BizType bizType, String purpose) {
        cache.asMap().entrySet().removeIf(entry -> {
            CachedDataKey v = entry.getValue();
            boolean snMatch = deviceSn == null || deviceSn.equals(v.getDeviceSn());
            boolean btMatch = bizType == null || bizType == v.getBizType();
            boolean purposeMatch = purpose == null || purpose.equals(v.getPurpose());
            return snMatch && btMatch && purposeMatch;
        });
    }

    /**
     * 使缓存失效
     *
     * @param keyId 密钥ID
     * @deprecated 使用 {@link #invalidateKey(String)}
     */
    @Deprecated
    public void invalidate(String keyId) {
        invalidateKey(keyId);
    }

    private WrappedKey toWrappedKey(WrappedBusinessKey wrapped) {
        WrappedKey key = new WrappedKey();
        key.setKeyId(wrapped.keyId());
        key.setKeyVersion(wrapped.kmsKeyVersion() != null ? wrapped.kmsKeyVersion() : 0);
        key.setWrappedDek(wrapped.wrapped());
        return key;
    }

    private int businessKeyVersionAsInt(long businessKeyVersion) {
        if (businessKeyVersion > Integer.MAX_VALUE || businessKeyVersion < Integer.MIN_VALUE) {
            throw new CryptoDependencyUnavailableException(
                    "businessKeyVersion 超出信封头可承载范围: " + businessKeyVersion);
        }
        return (int) businessKeyVersion;
    }

    private String buildCacheKey(String deviceSn, BizType bizType) {
        return deviceSn + ":" + bizType.name();
    }

    private String buildCacheKey(String keyId, long businessKeyVersion) {
        return keyId + ":" + businessKeyVersion;
    }
}
