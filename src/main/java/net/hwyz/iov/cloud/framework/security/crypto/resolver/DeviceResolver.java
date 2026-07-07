package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;

/**
 * 设备解析器接口
 */
public interface DeviceResolver {

    /**
     * 解析设备SN
     *
     * @param vin     VIN
     * @param bizType 业务类型
     * @return 设备SN
     */
    String resolveDeviceSn(String vin, BizType bizType);
}
