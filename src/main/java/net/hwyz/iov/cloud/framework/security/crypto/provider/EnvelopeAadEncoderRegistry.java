package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 信封 AAD Encoder 受控注册表（FW-SEC-DSN-CR-020 §2/§3）。
 * <p>
 * framework 通过本注册表解析 VMD 注册的协议 AAD profile；<strong>启动期冻结</strong>，
 * 禁止运行期热切换/替换（profile 由配置选定后冻结，幂等绑定不变）。
 * <p>
 * fail-closed 规则：
 * <ul>
 *   <li>null encoder、空白/非法 profileId → 拒绝注册；</li>
 *   <li>重复 profileId → 拒绝（启动 fail-closed）；</li>
 *   <li>固定向量自检：同 probe 上下文两次 {@code encode} 必须字节级一致
 *       （非确定性输出拒绝注册，FW-SEC-DSN-CR-020 §7 测试 3）；</li>
 *   <li>probe 输出为空或超过 {@code EcdhEsP256EnvelopeViewV1.MAX_CANONICAL_AAD_LENGTH}
 *       → 拒绝注册；</li>
 *   <li>{@code require(profileId)} 未注册 → {@code IllegalArgumentException}（fail-closed，
 *       不得回退到旧 FW AAD 或空 AAD）。</li>
 * </ul>
 * 注册表只依赖 SPI，不依赖任何协议 classpath（CR-015 RD-015-2）。
 */
public final class EnvelopeAadEncoderRegistry {

    /** 固定确定性自检 probe 上下文（非敏感，仅用于验证 encoder 确定性/有界输出）。 */
    private static final EnvelopeAadContext PROBE_CONTEXT = new EnvelopeAadContext(
            1,
            WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
            "probe-request",
            "V2C_COMM_ROOT",
            KeyPurpose.UPLINK_AEAD,
            "logical-probe",
            7L,
            3L,
            "v1",
            new byte[32]);

    private final Map<String, EnvelopeAadEncoder> byProfileId;

    /**
     * 构造并冻结注册表：对每个 encoder 校验 profileId 合法性、唯一性与确定性自检。
     *
     * @param encoders 启动期收集的 encoder 列表（Spring 注入集合）
     * @throws IllegalStateException 存在 null/空白/重复 profileId、非确定性输出或超限输出
     */
    public EnvelopeAadEncoderRegistry(List<EnvelopeAadEncoder> encoders) {
        Objects.requireNonNull(encoders, "encoders must not be null");
        Map<String, EnvelopeAadEncoder> registered = new LinkedHashMap<>();
        for (EnvelopeAadEncoder encoder : encoders) {
            if (encoder == null) {
                throw new IllegalStateException("EnvelopeAadEncoder must not be null（FW-SEC-DSN-CR-020 §2）");
            }
            String profileId = encoder.profileId();
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalStateException(
                        "EnvelopeAadEncoder.profileId must not be null or blank: " + encoder.getClass().getName());
            }
            if (registered.containsKey(profileId)) {
                throw new IllegalStateException(
                        "duplicate EnvelopeAadEncoder profileId: " + profileId
                                + "（重复 profile 拒绝注册，FW-SEC-DSN-CR-020 §2）");
            }
            verifyDeterministic(encoder, profileId);
            registered.put(profileId, encoder);
        }
        this.byProfileId = Collections.unmodifiableMap(registered);
    }

    /**
     * 便捷构造。
     */
    public static EnvelopeAadEncoderRegistry of(EnvelopeAadEncoder... encoders) {
        return new EnvelopeAadEncoderRegistry(
                encoders == null ? List.of() : Arrays.asList(encoders));
    }

    /**
     * 解析指定 profile；未注册 fail-closed（不得回退旧 FW AAD/空 AAD）。
     *
     * @param profileId 协议 profile 标识
     * @return 已注册 encoder
     * @throws IllegalArgumentException profileId 未注册或非法
     */
    public EnvelopeAadEncoder require(String profileId) {
        if (profileId == null || profileId.isBlank()) {
            throw new IllegalArgumentException(
                    "aadProfileId must not be null or blank（FW-SEC-DSN-CR-020 §2）");
        }
        EnvelopeAadEncoder encoder = byProfileId.get(profileId);
        if (encoder == null) {
            throw new IllegalArgumentException(
                    "no EnvelopeAadEncoder registered for profileId=" + profileId
                            + "（可用: " + byProfileId.keySet() + "；未配置 profile 的 V2C 新 operation fail-closed）");
        }
        return encoder;
    }

    /**
     * 指定 profile 是否已注册。
     */
    public boolean has(String profileId) {
        return profileId != null && byProfileId.containsKey(profileId);
    }

    /**
     * 已注册 profile 标识集合（不可变）。
     */
    public Set<String> profileIds() {
        return byProfileId.keySet();
    }

    /**
     * 已注册 encoder 数量。
     */
    public int size() {
        return byProfileId.size();
    }

    /**
     * 是否为空注册表。
     */
    public boolean isEmpty() {
        return byProfileId.isEmpty();
    }

    /**
     * 固定向量确定性自检：同一 probe 上下文两次 encode 字节级一致，且输出非空、有界。
     */
    private static void verifyDeterministic(EnvelopeAadEncoder encoder, String profileId) {
        byte[] first;
        byte[] second;
        try {
            first = encoder.encode(PROBE_CONTEXT);
            second = encoder.encode(PROBE_CONTEXT);
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    "EnvelopeAadEncoder profileId=" + profileId + " encode 抛错，拒绝注册: " + e.getMessage(), e);
        }
        if (first == null || first.length == 0) {
            throw new IllegalStateException(
                    "EnvelopeAadEncoder profileId=" + profileId + " 输出为空，拒绝注册");
        }
        if (first.length > net.hwyz.iov.cloud.framework.security.crypto.model
                .EcdhEsP256EnvelopeViewV1.MAX_CANONICAL_AAD_LENGTH) {
            throw new IllegalStateException(
                    "EnvelopeAadEncoder profileId=" + profileId + " 输出超过 "
                            + net.hwyz.iov.cloud.framework.security.crypto.model
                            .EcdhEsP256EnvelopeViewV1.MAX_CANONICAL_AAD_LENGTH
                            + " 字节上限，拒绝注册");
        }
        if (!Arrays.equals(first, second)) {
            throw new IllegalStateException(
                    "EnvelopeAadEncoder profileId=" + profileId
                            + " 输出非确定性（同上下文两次编码不一致），拒绝注册"
                            + "（FW-SEC-DSN-CR-020 §7 测试 3）");
        }
    }
}
