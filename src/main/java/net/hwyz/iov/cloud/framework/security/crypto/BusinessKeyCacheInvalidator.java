package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;

/**
 * 业务密钥缓存失效器（FW-SEC-DSN-CR-009 §8）。
 * <p>
 * 消费方可将 VMD 的 {@code BusinessKeyChangedEvent} 映射到该接口主动失效缓存；
 * framework 不绑定具体 Kafka Topic。TTL 仍为故障兜底，不替代主动吊销收敛。
 */
public interface BusinessKeyCacheInvalidator {

    /**
     * 按 keyId 失效缓存。
     *
     * @param keyId 材料标识
     */
    void invalidateKey(String keyId);

    /**
     * 按设备维业务上下文失效缓存。
     *
     * @param deviceSn 设备 SN
     * @param bizType  业务类型
     * @param purpose  业务用途（可为 null，表示任意用途）
     */
    void invalidateContext(String deviceSn, BizType bizType, String purpose);
}
