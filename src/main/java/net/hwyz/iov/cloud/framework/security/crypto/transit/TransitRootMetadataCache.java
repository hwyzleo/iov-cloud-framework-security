package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Transit 根元数据缓存（FW-SEC-DSN-CR-019 §10/§11）。
 * <p>
 * 为信封 {@code rootKeyVersion} 与 readiness 提供根当前密钥版本；短 TTL 缓存避免每次
 * 派生都读取元数据。刷新失败时 fail-closed（不携带陈旧版本进入信封）。
 * 单飞刷新（同一根并发只刷一次）；策略与根映射不在请求处理中修改。
 */
public class TransitRootMetadataCache {

    private final TransitHmacClient client;
    private final Duration ttl;
    private final Clock clock;
    private final Map<String, CacheEntry> entries = new ConcurrentHashMap<>();
    private final Object lock = new Object();

    public TransitRootMetadataCache(TransitHmacClient client, Duration ttl) {
        this(client, ttl, Clock.systemUTC());
    }

    public TransitRootMetadataCache(TransitHmacClient client, Duration ttl, Clock clock) {
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.ttl = ttl == null || ttl.isZero() || ttl.isNegative()
                ? Duration.ofSeconds(60) : ttl;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    /**
     * 返回根当前密钥版本；缓存过期则单飞刷新（失败 fail-closed）。
     *
     * @param rootKeyName Transit 根密钥名
     * @return 当前密钥版本
     */
    public long currentKeyVersion(String rootKeyName) {
        Objects.requireNonNull(rootKeyName, "rootKeyName must not be null");
        Instant now = clock.instant();
        CacheEntry entry = entries.get(rootKeyName);
        if (entry != null && entry.validUntil.isAfter(now)) {
            return entry.version;
        }
        synchronized (lock) {
            entry = entries.get(rootKeyName);
            if (entry != null && entry.validUntil.isAfter(now)) {
                return entry.version;
            }
            TransitKeyMetadata metadata = client.readMetadata(rootKeyName);
            long version = metadata.currentKeyVersion();
            if (version <= 0) {
                throw TransitException.rootTypeMismatch(rootKeyName,
                        "current_key_version must be > 0");
            }
            entries.put(rootKeyName, new CacheEntry(version, now.plus(ttl)));
            return version;
        }
    }

    /**
     * 立即校验根元数据（readiness 用）；返回元数据并按 TTL 缓存。
     *
     * @param rootKeyName Transit 根密钥名
     * @return 根元数据
     */
    public TransitKeyMetadata validateAndCache(String rootKeyName) {
        Objects.requireNonNull(rootKeyName, "rootKeyName must not be null");
        TransitKeyMetadata metadata = client.readMetadata(rootKeyName);
        if (metadata.currentKeyVersion() <= 0) {
            throw TransitException.rootTypeMismatch(rootKeyName,
                    "current_key_version must be > 0");
        }
        entries.put(rootKeyName, new CacheEntry(metadata.currentKeyVersion(),
                clock.instant().plus(ttl)));
        return metadata;
    }

    /**
     * 清空缓存（测试/重配置用）。
     */
    public void clear() {
        entries.clear();
    }

    private record CacheEntry(long version, Instant validUntil) {
    }
}
