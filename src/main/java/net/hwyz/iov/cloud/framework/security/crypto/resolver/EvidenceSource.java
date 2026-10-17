package net.hwyz.iov.cloud.framework.security.crypto.resolver;

/**
 * 证书证据来源（FW-SEC-DSN-CR-012 §5/§6）。
 * <p>
 * 解析顺序：{@link #INLINE_DER} → {@link #INLINE_SPKI} → {@link #ENROLLMENT_STORE}
 * → {@link #PROVIDER_QUERY} → {@link #DOMAIN_DIRECTORY}。
 */
public enum EvidenceSource {
    /**
     * 调用方直接携带的叶子证书 DER
     */
    INLINE_DER,
    /**
     * 调用方直接携带的公钥 SPKI（仅 policy 允许裸公钥时）
     */
    INLINE_SPKI,
    /**
     * requestId → 证书注册结果存储 / 证书注册门面
     */
    ENROLLMENT_STORE,
    /**
     * Provider 具备 serial 查询能力时的按 serial 查询
     */
    PROVIDER_QUERY,
    /**
     * 领域目录 locator 间接取得的材料
     */
    DOMAIN_DIRECTORY
}
