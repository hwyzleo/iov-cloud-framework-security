package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyDescriptor;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.DeviceKeyContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyOperation;

/**
 * VMD 业务目录 Feign 客户端 SPI（FW-SEC-DSN-CR-009 §4 扩展点）。
 * <p>
 * framework 只定义该扩展点；生产实现由消费服务以 Feign 接入 VMD Service API，
 * 由 VMD 完成调用方、业务域/用途与唯一 ACTIVE 授权。framework 不内置 VMD 数据表。
 */
public interface VmdBusinessKeyDirectoryClient {

    /**
     * 由 VMD 解析设备维唯一 ACTIVE 业务密钥。
     *
     * @param context 设备维寻址上下文
     * @return 唯一 ACTIVE 描述；空/多值由 VMD 侧拒绝
     */
    BusinessKeyDescriptor resolveActive(DeviceKeyContext context);

    /**
     * 由 VMD 按 keyId 校验操作授权、业务状态与解密窗口。
     *
     * @param keyId     材料标识
     * @param operation 目标操作
     * @return 业务目录描述
     */
    BusinessKeyDescriptor resolveByKeyId(String keyId, KeyOperation operation);
}
