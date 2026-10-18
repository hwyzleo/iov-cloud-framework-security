package net.hwyz.iov.cloud.framework.security.crypto.client;

import java.util.Set;
import java.util.TreeSet;

/**
 * 业务密钥 Provider 能力声明（FW-SEC-DSN-CR-011 §6.5/§8.3；FW-SEC-DSN-CR-014 §9）。
 * <p>
 * 启动门禁与 readiness 的核心依据：Provider 版本/API 版本、mount/storage 状态、
 * 支持的算法、WrapMode、派生封装信封版本与结果存储就绪情况。
 * 不得包含 Secret、Token 或密钥清单。
 *
 * @param provider                Provider 身份（应与 crypto.kms.provider 契约期望值一致）
 * @param apiVersion              API 版本（应与 crypto.kms.business-key.api-version 契约期望值一致）
 * @param mount                   mount 名称（应与 crypto.kms.business-key.mount 契约期望值一致）
 * @param ready                   Provider 综合就绪（优先采用；缺省时由 storage/mount 推导）
 * @param storageReady            storage 是否就绪（Raft/barrier 可写）
 * @param mountReady              mount/插件是否就绪
 * @param algorithms              支持的算法（如 {@code ECDH_P256}、{@code HKDF_SHA256}、{@code AES_256_GCM}）
 * @param wrapModes               支持的 WrapMode（{@link net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode} 名称）
 * @param derivedEnvelopeVersions 支持的派生封装信封版本（如 {@code v1}）
 * @param resultStoreReady        幂等结果存储是否可写/可读/可对账（FW-SEC-DSN-CR-014 §6/§9）
 */
public record KmsProviderCapabilities(
        String provider,
        String apiVersion,
        String mount,
        boolean ready,
        boolean storageReady,
        boolean mountReady,
        Set<String> algorithms,
        Set<String> wrapModes,
        Set<String> derivedEnvelopeVersions,
        boolean resultStoreReady) {

    public KmsProviderCapabilities {
        algorithms = algorithms == null ? Set.of() : Set.copyOf(new TreeSet<>(algorithms));
        wrapModes = wrapModes == null ? Set.of() : Set.copyOf(new TreeSet<>(wrapModes));
        derivedEnvelopeVersions = derivedEnvelopeVersions == null
                ? Set.of() : Set.copyOf(new TreeSet<>(derivedEnvelopeVersions));
    }

    /**
     * 向后兼容构造：未声明派生封装信封版本与结果存储（默认无信封版本、结果存储就绪）。
     *
     * @param provider     Provider 身份
     * @param apiVersion   API 版本
     * @param mount        mount 名称
     * @param ready        综合就绪
     * @param storageReady storage 就绪
     * @param mountReady   mount 就绪
     * @param algorithms   算法
     * @param wrapModes    WrapMode
     */
    public KmsProviderCapabilities(String provider, String apiVersion, String mount, boolean ready,
                                   boolean storageReady, boolean mountReady, Set<String> algorithms,
                                   Set<String> wrapModes) {
        this(provider, apiVersion, mount, ready, storageReady, mountReady, algorithms, wrapModes,
                Set.of(), true);
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
     * 是否声明支持指定派生封装信封版本（FW-SEC-DSN-CR-014 §9）。
     *
     * @param version 信封版本（如 {@code v1}）
     */
    public boolean supportsDerivedEnvelope(String version) {
        return version != null && derivedEnvelopeVersions.contains(version);
    }

    /**
     * 是否声明支持指定算法（FW-SEC-DSN-CR-014 §9）。
     *
     * @param algorithm 算法标记（如 {@code ECDH_P256}）
     */
    public boolean supportsAlgorithm(String algorithm) {
        return algorithm != null && algorithms.contains(algorithm);
    }

    /**
     * fail-closed 兜底：未探测/探测失败时的 DOWN 能力声明。
     */
    public static KmsProviderCapabilities down() {
        return new KmsProviderCapabilities(null, null, null, false, false, false,
                Set.of(), Set.of(), Set.of(), false);
    }
}
