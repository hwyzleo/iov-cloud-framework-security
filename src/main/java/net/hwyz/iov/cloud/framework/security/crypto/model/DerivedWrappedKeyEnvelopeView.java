package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 派生封装信封的<strong>结构化、只读、版本化</strong>视图（FW-SEC-DSN-CR-015 §4.1）。
 * <p>
 * 业务消费者（VMD/VAGW/TSP）SHALL 通过本视图读取信封公开字段，<strong>禁止</strong>解析
 * {@code DerivedWrappedKey.envelopeBytes} 的私有 canonical 格式（FW-SEC-DSN-CR-015 RD-015-1/§5）。
 * 视图只暴露非敏感元数据与受控密文材料，<strong>不含</strong>临时私钥、ECDH shared secret、
 * KEK 或业务密钥明文。
 * <p>
 * 首期唯一实现为 {@link EcdhEsP256EnvelopeViewV1}（信封格式 {@code ECDH_ES_P256_V1}）；
 * 新增信封格式走 CR + framework 发版并扩展 {@code permits} 列表。
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
     * 由 framework 权威 canonical 编码器唯一负责（FW-SEC-DSN-CR-014 §4；CR-015 RD-015-4）。
     *
     * @return 32 字节摘要副本
     */
    byte[] envelopeDigest();

    /**
     * 密钥校验值 KCV（{@code first_3_bytes(SHA-256(businessKey))}）。
     *
     * @return 3 字节 KCV 副本
     */
    byte[] keyCheckValue();
}
