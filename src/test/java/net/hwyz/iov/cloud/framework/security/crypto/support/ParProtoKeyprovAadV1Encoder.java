package net.hwyz.iov.cloud.framework.security.crypto.support;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadContext;
import net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoder;

/**
 * PAR-PROTO keyprov AAD profile 契约夹具（FW-SEC-DSN-CR-020 §2/§7 测试 1）。
 * <p>
 * 模拟 VMD 注册的 PAR-PROTO {@code PAR_PROTO_KEYPROV_AAD_V1} profile 输出：
 * <strong>确定性</strong>（同上下文字节级一致）、有界（≤ 1 KiB）。权威字节向量
 * 由 {@link #AUTHORITY_VECTOR_HEX} 冻结，供 readiness 权威向量自检与跨端对齐
 * （真实 PAR-PROTO 向量由 VMD 联调后替换本夹具输出与冻结向量）。
 * <p>
 * 编码规则（长度前缀 + UTF-8，与 core canonical 区分）：
 * <pre>
 * "openiov|keyprov-aad|v1" + formatVersion + wrappingSuite.wireName
 *   + requestId + businessDomain + purpose.name() + logicalKeyId
 *   + businessKeyVersion + rootKeyVersion + derivationVersion
 *   + recipientCertificateDigest(hex lower)
 * </pre>
 */
public class ParProtoKeyprovAadV1Encoder implements EnvelopeAadEncoder {

    /** profile 标识（对应配置 {@code crypto.provisioning.derived-key.aad-profile-id}）。 */
    public static final String PROFILE_ID = "PAR_PROTO_KEYPROV_AAD_V1";

    /**
     * 固定 probe 上下文（与 {@code EnvelopeAadEncoderRegistry} probe 相同）上的权威向量
     * （十六进制小写）。由 VMD PAR-PROTO 联调对齐后替换本夹具输出与冻结向量。
     */
    public static final String AUTHORITY_VECTOR_HEX =
            "000000166f70656e696f767c6b657970726f762d6161647c7631"   // openiov|keyprov-aad|v1 (22B)
                    + "0000000131"                                                   // formatVersion=1
                    + "0000000f454344482d45532b4132353647434d"                       // wireName ECDH-ES+A256GCM
                    + "0000000d70726f62652d72657175657374"                           // requestId
                    + "0000000d5632435f434f4d4d5f524f4f54"                           // businessDomain
                    + "0000000b55504c494e4b5f41454144"                               // purpose
                    + "0000000d6c6f676963616c2d70726f6265"                           // logicalKeyId
                    + "0000000137"                                                   // businessKeyVersion=7
                    + "0000000133"                                                   // rootKeyVersion=3
                    + "000000027631"                                                 // derivationVersion=v1
                    + "000000403030303030303030303030303030303030303030303030303030303030303030"
                    + "3030303030303030303030303030303030303030303030303030303030303030"; // digest hex

    @Override
    public String profileId() {
        return PROFILE_ID;
    }

    @Override
    public byte[] encode(EnvelopeAadContext context) {
        return CanonicalEncoding.lengthPrefixedUtf8(
                "openiov|keyprov-aad|v1",
                Integer.toString(context.formatVersion()),
                context.wrappingSuite() == null ? null : context.wrappingSuite().wireName(),
                context.requestId(),
                context.businessDomain(),
                context.purpose() == null ? null : context.purpose().name(),
                context.logicalKeyId(),
                Long.toString(context.businessKeyVersion()),
                Long.toString(context.rootKeyVersion()),
                context.derivationVersion(),
                CanonicalEncoding.hexLower(context.recipientCertificateDigest()));
    }
}
