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

    private static final Set<String> SUPPORTED = Set.of(STRUCTURED_ENVELOPE_VIEW_V1,
            CORE_ENVELOPE_DIGEST_VERIFY_V1);

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
        return capability != null && SUPPORTED.contains(capability);
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
