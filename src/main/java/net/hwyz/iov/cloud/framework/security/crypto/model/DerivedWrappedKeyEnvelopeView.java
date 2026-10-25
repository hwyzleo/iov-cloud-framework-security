package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 派生封装信封的<strong>结构化、只读、版本化</strong>视图（FW-SEC-DSN-CR-015 §4.1；
 * FW-SEC-DSN-CR-020 §2）。
 * <p>
 * 业务消费者（VMD/VAGW/TSP）SHALL 通过本视图读取信封公开字段，<strong>禁止</strong>解析
 * {@code DerivedWrappedKey.envelopeBytes} 的私有 canonical 格式（FW-SEC-DSN-CR-015 RD-015-1/§5）。
 * 视图只暴露非敏感元数据与受控密文材料，<strong>不含</strong>临时私钥、ECDH shared secret、
 * KEK 或业务密钥明文。
 * <p>
 * 首期唯一实现为 {@link EcdhEsP256EnvelopeViewV1}（信封格式 {@code ECDH_ES_P256_V1}）；
 * 新增信封格式走 CR + framework 发版并扩展 {@code permits} 列表。
 * <p>
 * <strong>CR-020 演进</strong>：AAD 由协议无关 {@code EnvelopeAadEncoder} SPI 在加密前生成，
 * 视图显式暴露 {@link #canonicalAad()} / {@link #aadDigest()} / {@link #coreEnvelopeDigest()} /
 * {@link #aadProfileId()}；{@link #envelopeDigest()} 保留为 deprecated 委托 core 值
 * （FW-SEC-DSN-CR-020 §2/§6：新 V2C Adapter 必须使用 {@link #coreEnvelopeDigest()}）。
 * <p>
 * 所有 {@code byte[]} 访问器 SHALL 返回防御性副本，保证视图不可被外部改写。
 */
public sealed interface DerivedWrappedKeyEnvelopeView
        permits EcdhEsP256EnvelopeViewV1 {

    /**
     * 受治理信封格式标识（如 {@link EcdhEsP256EnvelopeViewV1#ENVELOPE_FORMAT}）。
     */
    String envelopeFormat();

    /**
     * 信封格式版本（首期 {@link EcdhEsP256EnvelopeViewV1#FORMAT_VERSION_V1}）。
     */
    int formatVersion();

    /**
     * 封装套件；必须与顶层 {@code DerivedWrappedKey} 一致。
     */
    WrappingSuite wrappingSuite();

    /**
     * 信封摘要（{@code SHA-256(canonicalEnvelopeBytesWithoutDigest)}），
     * 由 framework 权威 canonical 编码器唯一负责（FW-SEC-DSN-CR-014 §4；CR-015 RD-015-4；
     * CR-020 §2：core 18 字段 canonical 收口为 {@code coreEnvelopeDigest}）。
     *
     * @return 32 字节摘要副本
     * @deprecated 由 {@link #coreEnvelopeDigest()} 取代（FW-SEC-DSN-CR-020 §6）；
     * 新 V2C Adapter 禁止调用本方法，仅兼容旧消费者读取。
     */
    @Deprecated
    byte[] envelopeDigest();

    /**
     * 密钥校验值 KCV（{@code first_3_bytes(SHA-256(businessKey))}）。
     *
     * @return 3 字节 KCV 副本
     */
    byte[] keyCheckValue();

    /**
     * 实际使用的 canonical AAD 原始字节（协议 profile 输出或 legacy core AAD）。
     * AES-256-GCM 加密前注入的同一字节，禁止加密后替换（FW-SEC-DSN-CR-020 §3）。
     *
     * @return canonical AAD 副本（≤ 1 KiB）
     */
    byte[] canonicalAad();

    /**
     * AAD 摘要（{@code SHA-256(canonicalAad)}，32 字节）。
     *
     * @return 32 字节摘要副本
     */
    byte[] aadDigest();

    /**
     * core 信封摘要（{@code SHA-256(coreCanonicalEnvelopeBytesWithoutDigest)}），
     * 由 framework core canonical 编码器唯一负责；{@link #envelopeDigest()} 委托本值。
     *
     * @return 32 字节摘要副本
     */
    byte[] coreEnvelopeDigest();

    /**
     * 使用的 AAD profile 标识（{@code null} 表示无 profile 的旧格式/legacy core AAD）。
     * 新 V2C 结果必须非空（FW-SEC-DSN-CR-020 §6）。
     *
     * @return profile 标识或 null
     */
    String aadProfileId();
}
