package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyDescriptor;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.DeviceKeyContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyOperation;

/**
 * 业务密钥目录 SPI（FW-SEC-DSN-CR-009 §4）。
 * <p>
 * 受 {@code crypto.business-key.directory.enabled} 控制 Resolver Adapter 装配。
 * 默认生产实现由消费服务接入 VMD Service API；framework-starter 只定义 SPI 和
 * Feign Adapter 扩展点（{@link VmdBusinessKeyDirectoryClient}），不内置 VMD 数据表。
 * <p>
 * 契约（fail-closed）：
 * <ul>
 *   <li>{@code resolveActive} 只能返回一个 ACTIVE；空、多值或状态不一致均抛目录异常并 fail-closed</li>
 *   <li>{@code resolveByKeyId} 对 DEPRECATED 的可解密窗口作权威判断；REVOKED/EXPIRED 拒绝</li>
 *   <li>Resolver 必须完成调用方、业务域/用途和状态授权；framework 不重复解释这些业务规则</li>
 * </ul>
 */
public interface BusinessKeyDirectoryResolver {

    /**
     * 解析设备维唯一 ACTIVE 业务密钥。
     *
     * @param context 设备维寻址上下文
     * @return 唯一 ACTIVE 描述（空/多值/状态不一致抛目录异常）
     */
    BusinessKeyDescriptor resolveActive(DeviceKeyContext context);

    /**
     * 按 keyId 反向寻址并校验操作授权与业务状态/解密窗口。
     *
     * @param keyId     信封头携带的材料标识
     * @param operation 目标操作（ENCRYPT/DECRYPT）
     * @return 业务目录描述（REVOKED/EXPIRED 拒绝；DEPRECATED 由解密窗口判定）
     */
    BusinessKeyDescriptor resolveByKeyId(String keyId, KeyOperation operation);
}
