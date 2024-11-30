package net.hwyz.iov.cloud.framework.security.util;

import cn.hutool.core.util.ObjUtil;
import cn.hutool.extra.spring.SpringUtil;
import com.alibaba.fastjson2.JSONArray;
import net.hwyz.iov.cloud.framework.common.constant.CacheConstants;
import net.hwyz.iov.cloud.framework.redis.service.RedisService;
import net.hwyz.iov.cloud.mpt.system.api.domain.SysDictData;

import java.util.Collection;
import java.util.List;

/**
 * 字典工具类
 *
 * @author hwyz_leo
 */
public class DictUtils {
    /**
     * 设置字典缓存
     *
     * @param key       参数键
     * @param dictDatas 字典数据列表
     */
    public static void setDictCache(String key, List<SysDictData> dictDatas) {
        SpringUtil.getBean(RedisService.class).setCacheObject(getCacheKey(key), dictDatas);
    }

    /**
     * 获取字典缓存
     *
     * @param key 参数键
     * @return dictDatas 字典数据列表
     */
    public static List<SysDictData> getDictCache(String key) {
        JSONArray arrayCache = SpringUtil.getBean(RedisService.class).getCacheObject(getCacheKey(key));
        if (ObjUtil.isNotNull(arrayCache)) {
            return arrayCache.toList(SysDictData.class);
        }
        return null;
    }

    /**
     * 删除指定字典缓存
     *
     * @param key 字典键
     */
    public static void removeDictCache(String key) {
        SpringUtil.getBean(RedisService.class).deleteObject(getCacheKey(key));
    }

    /**
     * 清空字典缓存
     */
    public static void clearDictCache() {
        Collection<String> keys = SpringUtil.getBean(RedisService.class).keys(CacheConstants.SYS_DICT_KEY + "*");
        SpringUtil.getBean(RedisService.class).deleteObject(keys);
    }

    /**
     * 设置cache key
     *
     * @param configKey 参数键
     * @return 缓存键key
     */
    public static String getCacheKey(String configKey) {
        return CacheConstants.SYS_DICT_KEY + configKey;
    }
}
