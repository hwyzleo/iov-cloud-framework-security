package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.DeviceUnboundException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.BindingEntry;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * 默认设备解析器实现
 */
@Component
public class DefaultDeviceResolver implements DeviceResolver {

    private final CryptoProperties properties;
    private final RestTemplate restTemplate;

    private Cache<String, BindingEntry> cache;

    public DefaultDeviceResolver(CryptoProperties properties) {
        this.properties = properties;
        this.restTemplate = new RestTemplate();
    }

    @PostConstruct
    public void init() {
        this.cache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(properties.getBindingCache().getTtl().toMillis(), TimeUnit.MILLISECONDS)
                .build();
    }

    @Override
    public String resolveDeviceSn(String vin, BizType bizType) {
        // 从BizType获取器件类别（ORG 锚定的非对称密钥无器件类别，不经过设备解析）
        String deviceCategory = bizType.getDeviceCategory() != null
                ? bizType.getDeviceCategory().name() : "UNKNOWN";

        // 查询缓存
        String cacheKey = buildCacheKey(vin, deviceCategory);
        BindingEntry cached = cache.getIfPresent(cacheKey);

        if (cached != null && !cached.getExpireAt().isBefore(Instant.now())) {
            if (!"ACTIVE".equals(cached.getStatus())) {
                throw new DeviceUnboundException("Device not active: " + vin);
            }
            return cached.getDeviceSn();
        }

        // 缓存未命中，查询VMD/TSP服务
        try {
            BindingEntry entry = queryBinding(vin, deviceCategory);
            if (entry == null || !"ACTIVE".equals(entry.getStatus())) {
                throw new DeviceUnboundException("Device not bound or not active: " + vin);
            }

            cache.put(cacheKey, entry);
            return entry.getDeviceSn();
        } catch (DeviceUnboundException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to resolve device binding", e);
        }
    }

    private BindingEntry queryBinding(String vin, String deviceCategory) {
        // TODO: 实现VMD/TSP服务调用
        // 这里应该调用VMD/TSP服务的绑定查询接口
        // 暂时返回模拟数据
        BindingEntry entry = new BindingEntry();
        entry.setVin(vin);
        entry.setDeviceCategory(deviceCategory);
        entry.setDeviceSn("SN_" + vin); // 模拟数据
        entry.setStatus("ACTIVE");
        entry.setExpireAt(Instant.now().plus(properties.getBindingCache().getTtl()));
        return entry;
    }

    private String buildCacheKey(String vin, String deviceCategory) {
        return vin + ":" + deviceCategory;
    }
}
