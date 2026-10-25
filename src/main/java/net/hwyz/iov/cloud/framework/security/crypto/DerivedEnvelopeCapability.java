package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalDerivedEnvelopeDigestVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedEnvelopeDigestVerifier;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeView;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Set;

/**
 * 派生封装信封能力声明（FW-SEC-DSN-CR-015 §4.3/§7）。
 * <p>
 * 用于声明 framework 侧是否具备结构化 envelope view、公开 canonical verifier 与
 * PAR-PROTO wire 下发能力，供 readiness/对账与业务消费者（VMD）门禁使用。
 * <p>
 * <strong>本仓范围（CR-015 决议）</strong>：framework-security 交付
 * {@link #STRUCTURED_ENVELOPE_VIEW_V1}（core 结构化视图）与
 * {@link #CORE_ENVELOPE_DIGEST_VERIFY_V1}（公开 canonical verifier）。PAR-PROTO 字段映射
 * （{@link #PAR_PROTO_WIRE_MAPPER_V1} / {@link #DETERMINISTIC_PARAMETERS_V1} /
 * {@link #WIRE_DIGEST_SELF_CHECK_V1}）作为 VMD 协议 Adapter 的职责，本 artifact
 * <strong>不</strong>声明支持；bridge artifact 缺失时新的 envelope v1 wire 下发 capability
 * 保持 DOWN，禁止回退到私有 {@code envelopeBytes} 解析或空 parameters
 * （CR-015 §5/§7；REQ-015-2/REQ-015-5）。
 * <p>
 * 依据 CR-015 决议，framework core 的 canonical {@code envelopeDigest} 为唯一权威，
 * PAR-PROTO 侧只无损承载，不重新定义 framing digest。
 */
public final class DerivedEnvelopeCapability {

    /**
     * core 暴露结构化、只读、版本化 envelope view（{@code EcdhEsP256EnvelopeViewV1}）。
     */
    public static final String STRUCTURED_ENVELOPE_VIEW_V1 = "STRUCTURED_ENVELOPE_VIEW_V1";

    /**
     * core 公开可直接接收公开 view 的 canonical envelopeDigest 校验 API
     * （{@code DerivedEnvelopeDigestVerifier#verify(DerivedWrappedKeyEnvelopeView)}）。
     * <p>仅在公开 API 可调用、当前 format/version 已注册且固定向量通过时 READY
     * （{@link #coreDigestVerifyReady()}）；仅存在接受私有类型的内部重载<strong>不</strong>满足。</p>
     */
    public static final String CORE_ENVELOPE_DIGEST_VERIFY_V1 = "CORE_ENVELOPE_DIGEST_VERIFY_V1";

    /**
     * FW→PAR-PROTO wire mapper（{@code wrapped_key} ciphertext + deterministic parameters）。
     * <p>由 VMD 协议 Adapter / 可选 integration artifact 提供，本 artifact 不声明支持。</p>
     */
    public static final String PAR_PROTO_WIRE_MAPPER_V1 = "PAR_PROTO_WIRE_MAPPER_V1";

    /**
     * deterministic Protobuf parameters 序列化能力（PAR-PROTO 侧）。
     * <p>本 artifact 不声明支持。</p>
     */
    public static final String DETERMINISTIC_PARAMETERS_V1 = "DETERMINISTIC_PARAMETERS_V1";

    /**
     * wire digest 自校验能力（重算并与 FW 原 {@code envelopeDigest} 常量时间比较）。
     * <p>core 侧自校验由 {@code DerivedKeyEnvelopeCanonical#verifyEnvelopeDigest} 提供；
     * wire 级自校验由 PAR-PROTO Adapter 提供，本 artifact 不声明后者。</p>
     */
    public static final String WIRE_DIGEST_SELF_CHECK_V1 = "WIRE_DIGEST_SELF_CHECK_V1";

    /**
     * 外部 AAD profile 能力（FW-SEC-DSN-CR-020 §5）：framework 通过受控
     * {@code EnvelopeAadEncoderRegistry} 解析 VMD 注册的协议 AAD profile，并在 AES-GCM
     * 加密前注入 canonical AAD。READY 需：aadProfileId 已配置、profile 可解析、权威向量通过
     * 与 Provider/result store 能力（{@code externalAadProfileReady}）。
     */
    public static final String EXTERNAL_AAD_PROFILE_V1 = "EXTERNAL_AAD_PROFILE_V1";

    /**
     * PAR-PROTO keyprov AAD profile 能力（FW-SEC-DSN-CR-020 §5，Java 常量下划线形式）。
     * <p>对外规范化 capability ID 为 {@link #AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1_WIRE_ID}
     * （Health/readiness/日志/能力清单使用，经 {@link #wireId} 显式映射，不依赖自动转换）。</p>
     */
    public static final String AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1 =
            "AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1";

    /**
     * PAR-PROTO keyprov AAD profile 对外规范化 wire ID
     * （{@code AAD_PROFILE[PAR_PROTO_KEYPROV_AAD_V1]}，FW-SEC-DSN-CR-020 §5）。
     */
    public static final String AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1_WIRE_ID =
            "AAD_PROFILE[PAR_PROTO_KEYPROV_AAD_V1]";

    private static final Set<String> SUPPORTED = Set.of(STRUCTURED_ENVELOPE_VIEW_V1,
            CORE_ENVELOPE_DIGEST_VERIFY_V1, EXTERNAL_AAD_PROFILE_V1,
            AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1);

    private DerivedEnvelopeCapability() {
    }

    /**
     * 本 artifact 声明支持的能力集合（不可变）。
     */
    public static Set<String> supported() {
        return SUPPORTED;
    }

    /**
     * 是否声明支持指定能力。
     *
     * @param capability 能力标识
     */
    public static boolean supports(String capability) {
        if (capability == null) {
            return false;
        }
        return SUPPORTED.contains(capability)
                || (AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1_WIRE_ID.equals(capability)
                && SUPPORTED.contains(AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1));
    }

    /**
     * 对外规范化 capability ID（FW-SEC-DSN-CR-020 §5）：
     * Health/readiness/日志/对外能力清单使用；Java 常量下划线形式与 wire 形式显式映射，
     * 不依赖 {@code enum.name()} 自动转换。
     *
     * @param capability Java 常量下划线形式
     * @return 对外 wire ID
     */
    public static String wireId(String capability) {
        if (AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1.equals(capability)) {
            return AAD_PROFILE_PAR_PROTO_KEYPROV_AAD_V1_WIRE_ID;
        }
        return capability == null ? null : capability;
    }

    /**
     * 判定 {@link #EXTERNAL_AAD_PROFILE_V1} 是否 READY（FW-SEC-DSN-CR-020 §5）。
     * <p>
     * READY 需同时满足：{@code aadProfileId} 已配置；受控 registry 可解析当前 profile
     * （SPI 已装配）；固定 probe 上下文的确定性/有界输出自检通过（PAR-PROTO 权威字节向量由
     * VMD 联调对齐，见契约夹具向量测试）；Provider/result store 能力可用
     * （生产要求共享、持久化、原子写入；InMemory 仅在显式允许 dev/test 时支撑 READY）。
     * <p>
     * 不验证 Proto classpath（CR-015 RD-015-2）：FW readiness 不依赖协议实现。
     *
     * @param registry        AAD encoder 受控注册表
     * @param aadProfileId    配置的 profile 标识
     * @param resultStore     Operation 结果存储
     * @param allowInMemory   dev/test 是否允许 InMemory 支撑 READY
     * @return 未就绪稳定 reason；READY 返回 null
     */
    public static String externalAadProfileReadyReason(
            Object registry,
            String aadProfileId,
            Object resultStore,
            boolean allowInMemory) {
        if (aadProfileId == null || aadProfileId.isBlank()) {
            return "AAD_PROFILE_NOT_CONFIGURED: 未配置 crypto.provisioning.derived-key.aad-profile-id"
                    + "（新 V2C ECDH-ES keyprov 必须配置外部 AAD profile，FW-SEC-DSN-CR-020 §6）";
        }
        if (registry == null) {
            return "AAD_PROFILE_UNAVAILABLE: EnvelopeAadEncoderRegistry 未装配（无 SPI bean）";
        }
        if (!(registry instanceof net.hwyz.iov.cloud.framework.security.crypto.provider
                .EnvelopeAadEncoderRegistry r) || !r.has(aadProfileId)) {
            return "AAD_PROFILE_UNAVAILABLE: 配置的 profileId=" + aadProfileId
                    + " 未注册（受控 registry 拒绝运行时替换）";
        }
        if (!probeSelfCheck((net.hwyz.iov.cloud.framework.security.crypto.provider
                .EnvelopeAadEncoderRegistry) registry, aadProfileId)) {
            return "AAD_ENCODER_OUTPUT_INVALID: 当前 profile 固定 probe 自检失败"
                    + "（非确定/超限/抛错，权威向量由 VMD 联调对齐）";
        }
        if (resultStore == null) {
            return "RESULT_STORE_UNAVAILABLE: Operation Result Store 未装配"
                    + "（字节级幂等重放必需，FW-SEC-DSN-CR-020 §4）";
        }
        if (!(resultStore instanceof net.hwyz.iov.cloud.framework.security.crypto.provider
                .OperationResultStore s)) {
            return "RESULT_STORE_UNAVAILABLE: Operation Result Store 类型非法";
        }
        if (!s.productionReady() && !allowInMemory) {
            return "RESULT_STORE_UNAVAILABLE: 结果存储类型=" + s.storeType()
                    + " 非生产级（需共享、持久化、原子写入；InMemory 仅 dev/test"
                    + " 且显式 allow-in-memory=true 时支撑 READY，FW-SEC-DSN-CR-020 §5）";
        }
        return null;
    }

    /**
     * 固定 probe 上下文自检：encoder 输出确定性、非空、有界（FW-SEC-DSN-CR-020 §7 测试 3 代理）。
     */
    static boolean probeSelfCheck(
            net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoderRegistry registry,
            String profileId) {
        try {
            net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoder encoder =
                    registry.require(profileId);
            net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadContext probe =
                    new net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadContext(
                            1,
                            net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite
                                    .ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                            "probe-request",
                            "V2C_COMM_ROOT",
                            net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose.UPLINK_AEAD,
                            "logical-probe",
                            7L,
                            3L,
                            "v1",
                            new byte[32]);
            byte[] first = encoder.encode(probe);
            byte[] second = encoder.encode(probe);
            return first != null && first.length > 0
                    && first.length <= net.hwyz.iov.cloud.framework.security.crypto.model
                            .EcdhEsP256EnvelopeViewV1.MAX_CANONICAL_AAD_LENGTH
                    && java.util.Arrays.equals(first, second);
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * {@link #EXTERNAL_AAD_PROFILE_V1} 是否 READY。
     */
    public static boolean externalAadProfileReady(Object registry, String aadProfileId,
                                                  Object resultStore, boolean allowInMemory) {
        return externalAadProfileReadyReason(registry, aadProfileId, resultStore, allowInMemory) == null;
    }

    /**
     * 判定 {@link #CORE_ENVELOPE_DIGEST_VERIFY_V1} 是否 READY（FW-SEC-DSN-CR-015 §7）。
     * <p>
     * READY 需同时满足：公开 {@code verify(DerivedWrappedKeyEnvelopeView)} 可调用（非仅私有类型重载）、
     * 当前 format/version 已注册、冻结向量自检通过。仅存在接受私有 {@code DerivedWrappedKeyEnvelopeV1}
     * 的内部方法<strong>不</strong>满足本 capability。
     */
    public static boolean coreDigestVerifyReady() {
        return coreDigestVerifyReady(DerivedEnvelopeDigestVerifier.class);
    }

    /**
     * 可测试的 READY 判定（指定待检查的公开 API 类型）。
     */
    static boolean coreDigestVerifyReady(Class<?> publicApi) {
        return publicVerifyApiAvailable(publicApi) && CanonicalDerivedEnvelopeDigestVerifier.selfCheck();
    }

    /**
     * 公开 API 是否暴露 {@code public void verify(DerivedWrappedKeyEnvelopeView)}。
     * <p>仅有接受私有类型的重载时返回 false（REQ-015-3）。</p>
     */
    static boolean publicVerifyApiAvailable(Class<?> api) {
        if (api == null || !api.isInterface()) {
            return false;
        }
        try {
            Method verify = api.getMethod("verify", DerivedWrappedKeyEnvelopeView.class);
            return Modifier.isPublic(verify.getModifiers()) && verify.getReturnType() == void.class;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }
}
