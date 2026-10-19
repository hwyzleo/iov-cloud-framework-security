package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Set;

/**
 * 导入证明 canonical 输入（FW-SEC-DSN-CR-014 §8；FW-SEC-DSN-CR-016 §3/§4）。
 * <p>
 * TBOX-SEC 在双用途原子提交成功后，使用本次 provisioning 绑定的 ACTIVE 设备身份私钥，
 * 对如下 canonical 输入产生 {@code ECDSA_P256_SHA256_P1363} Import Attestation
 * （bound to {@code envelopeDigest + KCV}）：
 * <pre>
 * proofInputV1 = lengthPrefixed(
 *   UTF8("openiov|keyprov-ack|v1"),
 *   UTF8(requestId),
 *   UTF8(businessDomain),
 *   unsignedVarint(purpose.canonicalValue()),
 *   SHA-256(UTF8(keyId)),
 *   uint64be(businessKeyVersion),
 *   envelopeDigest,
 *   keyCheckValue
 * )
 * </pre>
 * <strong>扁平 8 段</strong>编码，字段顺序固定，禁止嵌套或本地字符集。
 * <p>
 * {@link #proofInputV1} 是 keyprov-v1 唯一有效的生产 canonical 契约
 * （与 TBOX-SEC-DSN-CR-020 §7.3 / VMD-DSN-CR-062 §7 对齐）；{@link ImportProofVerifier}
 * <strong>禁止</strong>调用 {@link #proofInput}。
 * <p>
 * framework 只提供 canonical builder 与验证工具，<strong>不</strong>持有业务密钥；
 * KCV 仅用于材料一致性校验，不替代 AEAD tag 或设备持钥证明。
 */
public final class ImportProofCanonical {

    /** 导入证明协议标签（首期） */
    public static final String PROOF_LABEL = "openiov|keyprov-ack|v1";

    /**
     * 首期 proofInputV1 允许的业务域（FW-SEC-DSN-CR-016 §3/§4.1：精确值 {@code V2C_COMM}，
     * 区分大小写，禁止 trim、大小写转换、别名或 fallback）。
     * <p>
     * {@code V2C_COMM_ROOT} 仅表示根派生标识，<strong>不是</strong>业务域，作为 proof
     * businessDomain 必须 fail-closed 拒绝；{@link #isAllowedBusinessDomainV1} 只接受本常量。
     */
    public static final String ALLOWED_BUSINESS_DOMAIN_V1 = "V2C_COMM";

    private static final Set<String> ALLOWED_BUSINESS_DOMAINS_V1 = Set.of(ALLOWED_BUSINESS_DOMAIN_V1);

    private ImportProofCanonical() {
    }

    /**
     * 构造导入证明 canonical 输入（keyprov-v1 唯一有效生产契约）。
     * <p>
     * 内部固定执行：{@code keyIdDigest = SHA-256(UTF8(keyId))}、
     * {@code purpose = unsignedVarint(purpose.canonicalValue())}、
     * {@code businessKeyVersion = uint64be(businessKeyVersion)}。
     *
     * @param requestId          请求标识（非空白）
     * @param businessDomain     业务域（须为 {@link #ALLOWED_BUSINESS_DOMAIN_V1}，精确匹配）
     * @param purpose            派生用途（canonicalValue 必须 &gt; 0）
     * @param keyId              逻辑密钥标识（非空白，内部摘要为 32 字节）
     * @param businessKeyVersion VMD 业务版本（须为 1..2^63-1）
     * @param envelopeDigest     信封摘要
     * @param keyCheckValue      密钥校验值
     * @return canonical 输入字节
     */
    public static byte[] proofInputV1(String requestId, String businessDomain, KeyPurpose purpose,
                                      String keyId, long businessKeyVersion,
                                      byte[] envelopeDigest, byte[] keyCheckValue) {
        String domain = requireNonBlank(businessDomain, "businessDomain");
        if (!isAllowedBusinessDomainV1(domain)) {
            // fail-closed：禁止 trim、大小写转换、别名或 fallback
            throw new IllegalArgumentException(
                    "businessDomain not allowed for import-proof v1: " + domain);
        }
        String rid = requireNonBlank(requestId, "requestId");
        String kid = requireNonBlank(keyId, "keyId");
        Objects.requireNonNull(purpose, "purpose must not be null");
        if (purpose.canonicalValue() <= 0) {
            throw new IllegalArgumentException(
                    "purpose.canonicalValue must be > 0 for import-proof v1: " + purpose.canonicalValue());
        }
        Objects.requireNonNull(envelopeDigest, "envelopeDigest must not be null");
        Objects.requireNonNull(keyCheckValue, "keyCheckValue must not be null");

        byte[] keyIdDigest = CanonicalEncoding.sha256(kid.getBytes(StandardCharsets.UTF_8));
        return CanonicalEncoding.lengthPrefixed(
                PROOF_LABEL.getBytes(StandardCharsets.UTF_8),
                rid.getBytes(StandardCharsets.UTF_8),
                domain.getBytes(StandardCharsets.UTF_8),
                CanonicalEncoding.unsignedVarint(purpose.canonicalValue()),
                keyIdDigest,
                CanonicalEncoding.uint64be(businessKeyVersion),
                envelopeDigest,
                keyCheckValue);
    }

    /**
     * 业务域是否为首期 proofInputV1 允许值（精确匹配）。
     *
     * @param businessDomain 业务域
     * @return 允许返回 true
     */
    public static boolean isAllowedBusinessDomainV1(String businessDomain) {
        return businessDomain != null && ALLOWED_BUSINESS_DOMAINS_V1.contains(businessDomain);
    }

    /**
     * 构造导入证明 canonical 输入（<strong>legacy</strong>，非 keyprov-v1 生产契约）。
     * <p>
     * 该实现将 {@code keyIdDigest} 视为 UTF-8 字符串、{@code businessKeyVersion} 用十进制字符串、
     * {@code purpose} 用 {@code name()}，并把前 6 段嵌套为单一段——<strong>与
     * TBOX-SEC-DSN-CR-020 §7.3 / VMD-DSN-CR-062 §7 的 wire 定义不一致</strong>，
     * 无法与设备端 C++ 实现互通。
     *
     * @param requestId          请求标识
     * @param businessDomain     业务域
     * @param purpose            派生用途
     * @param keyIdDigest        逻辑密钥标识摘要（legacy 语义：UTF-8 字符串）
     * @param businessKeyVersion VMD 业务版本
     * @param envelopeDigest     信封摘要
     * @param kcv                密钥校验值
     * @return canonical 输入字节
     * @deprecated 仅为二进制/API 兼容保留；生产验签必须使用 {@link #proofInputV1}。
     */
    @Deprecated(forRemoval = true)
    public static byte[] proofInput(String requestId, String businessDomain, KeyPurpose purpose,
                                    String keyIdDigest, long businessKeyVersion,
                                    byte[] envelopeDigest, byte[] kcv) {
        return CanonicalEncoding.lengthPrefixed(
                CanonicalEncoding.lengthPrefixedUtf8(
                        PROOF_LABEL,
                        requestId,
                        businessDomain,
                        purpose == null ? null : purpose.name(),
                        keyIdDigest,
                        Long.toString(businessKeyVersion)),
                envelopeDigest,
                kcv);
    }

    /**
     * 恒定时间校验导入证明。
     *
     * @param expectedProof 期望证明（framework/对端计算）
     * @param actualProof   实际证明（车端 ACK 携带）
     * @return 一致返回 true
     * @deprecated 仅用于 canonical 字节测试/比较，不代表密码学 proof 验证成功
     * （FW-SEC-DSN-CR-016 §2 RD-016-4）；生产验签使用
     * {@link net.hwyz.iov.cloud.framework.security.crypto.ImportProofVerifier}。
     */
    @Deprecated(forRemoval = true)
    public static boolean matches(byte[] expectedProof, byte[] actualProof) {
        return CanonicalEncoding.constantTimeEquals(expectedProof, actualProof);
    }

    private static String requireNonBlank(String value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
