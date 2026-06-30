package net.hwyz.iov.cloud.framework.security.crypto.resolver;

/**
 * 设备解析器接口
 */
public interface DeviceResolver {

    /**
     * 解析设备SN
     *
     * @param vin       VIN
     * @param bizDomain 业务域
     * @return 设备SN
     */
    String resolveDeviceSn(String vin, String bizDomain);
}
