package net.hwyz.iov.cloud.framework.security.crypto;

import java.util.Set;

/**
 * 派生封装信封能力声明（FW-SEC-DSN-CR-015 §7）。
 * <p>
 * 用于声明 framework 侧是否具备结构化 envelope view 与 PAR-PROTO wire 下发能力，供
 * readiness/对账与业务消费者（VMD）门禁使用。
 * <p>
 * <strong>本仓范围（CR-015 决议）</strong>：framework-security 只交付
 * {@link #STRUCTURED_ENVELOPE_VIEW_V1}（core 结构化视图）。PAR-PROTO 字段映射
 * （{@link #PAR_PROTO_WIRE_MAPPER_V1} / {@link #DETERMINISTIC_PARAMETERS_V1} /
 * {@link #WIRE_DIGEST_SELF_CHECK_V1}）作为 VMD 协议 Adapter 的职责，本 artifact
 * <strong>不</strong>声明支持；bridge artifact 缺失时新的 envelope v1 wire 下发 capability
 * 保持 DOWN，禁止回退到私有 {@code envelopeBytes} 解析或空 parameters
 * （CR-015 §7；REQ-015-5）。
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

    private static final Set<String> SUPPORTED = Set.of(STRUCTURED_ENVELOPE_VIEW_V1);

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
}
