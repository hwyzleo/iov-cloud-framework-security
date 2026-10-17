package net.hwyz.iov.cloud.framework.security.crypto.client;

import java.util.Set;
import java.util.TreeSet;

/**
 * 业务密钥 Provider 能力声明（FW-SEC-DSN-CR-011 §6.5/§8.3）。
 * <p>
 * 启动门禁与 readiness 的核心依据：Provider 版本/API 版本、mount/storage 状态、
 * 支持的算法与 WrapMode。不得包含 Secret、Token 或密钥清单。
 *
 * @param provider     Provider 身份（应与 crypto.kms.provider 契约期望值一致）
 * @param apiVersion   API 版本（应与 crypto.kms.business-key.api-version 契约期望值一致）
 * @param mount        mount 名称（应与 crypto.kms.business-key.mount 契约期望值一致）
 * @param ready        Provider 综合就绪（优先采用；缺省时由 storage/mount 推导）
 * @param storageReady storage 是否就绪（Raft/barrier 可写）
 * @param mountReady   mount/插件是否就绪
 * @param algorithms   支持的算法
 * @param wrapModes    支持的 WrapMode（{@link net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode} 名称）
 */
public record KmsProviderCapabilities(
        String provider,
        String apiVersion,
        String mount,
        boolean ready,
        boolean storageReady,
        boolean mountReady,
        Set<String> algorithms,
        Set<String> wrapModes) {

    public KmsProviderCapabilities {
        algorithms = algorithms == null ? Set.of() : Set.copyOf(new TreeSet<>(algorithms));
        wrapModes = wrapModes == null ? Set.of() : Set.copyOf(new TreeSet<>(wrapModes));
    }

    /**
     * Provider 是否 READY。
     */
    public boolean isReady() {
        return ready;
    }

    /**
     * 是否声明支持指定 WrapMode。
     *
     * @param mode WrapMode 名称
     */
    public boolean supportsWrapMode(String mode) {
        return mode != null && wrapModes.contains(mode);
    }

    /**
     * fail-closed 兜底：未探测/探测失败时的 DOWN 能力声明。
     */
    public static KmsProviderCapabilities down() {
        return new KmsProviderCapabilities(null, null, null, false, false, false,
                Set.of(), Set.of());
    }
}
