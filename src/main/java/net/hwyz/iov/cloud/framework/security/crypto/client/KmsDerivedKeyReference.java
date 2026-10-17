package net.hwyz.iov.cloud.framework.security.crypto.client;

import java.util.Objects;

/**
 * 根派生引用（FW-SEC-DSN-CR-013 §5/§11）。
 * <p>
 * 由 framework 受治理策略按 {@link net.hwyz.iov.cloud.framework.security.crypto.model.BizType} 映射而来，
 * <strong>不接受</strong>调用方任意传入。Provider 侧按 {@code bizType} 策略注册表路由到受治理根，
 * 因此 {@code rootKeyRef} 只作不透明引用/元数据，不参与 Provider 的权限决策。
 *
 * @param bizType   业务类型名（Provider 据此策略映射受治理根）
 * @param rootKeyRef 不透明根引用（如 {@code openbao-transit://transit/keys/v2c-comm-root}）
 */
public record KmsDerivedKeyReference(String bizType, String rootKeyRef) {

    public KmsDerivedKeyReference {
        Objects.requireNonNull(bizType, "bizType must not be null");
    }
}
