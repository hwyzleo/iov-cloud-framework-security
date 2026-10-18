package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 派生封装套件（FW-SEC-DSN-CR-014 §4/§7.1）。
 * <p>
 * 受治理的封闭集合，描述「KEK 派生 + AEAD 封装」的完整密码学套件。
 * 业务不得传入任意自由字符串；新增取值走 CR + framework 发版。
 * <p>
 * 首期 EC 收方固定为 {@link #ECDH_ES_P256_HKDF_SHA256_AES256GCM}；RSA 收方沿用
 * {@link #RSA_OAEP_SHA256}。收方公钥算法（EC / RSA）与套件一一对应，framework 侧
 * 由证书证据推导，不由调用方指定。
 */
public enum WrappingSuite {

    /**
     * EC 收方首期套件：ECDH-ES（NIST P-256）+ HKDF-SHA-256 + AES-256-GCM。
     * <p>
     * 服务端为每个新 operation 生成临时 P-256 密钥对，ECDH shared secret 经 HKDF-SHA-256
     * 派生 32 字节 KEK，业务密钥以 AES-256-GCM 封装（96-bit nonce，128-bit tag）。
     */
    ECDH_ES_P256_HKDF_SHA256_AES256GCM("ECDH-ES-P256/HKDF-SHA-256/AES-256-GCM",
            "ECDH-ES+A256GCM", "EC"),

    /**
     * RSA 收方套件：RSA-OAEP（SHA-256）+ 直接封装。
     */
    RSA_OAEP_SHA256("RSA-OAEP-SHA256", "RSA-OAEP-SHA256", "RSA");

    private final String spec;
    private final String wireName;
    private final String recipientKeyAlgorithm;

    WrappingSuite(String spec, String wireName, String recipientKeyAlgorithm) {
        this.spec = spec;
        this.wireName = wireName;
        this.recipientKeyAlgorithm = recipientKeyAlgorithm;
    }

    /**
     * 套件规范名（如 {@code ECDH-ES-P256/HKDF-SHA-256/AES-256-GCM}）。
     */
    public String spec() {
        return spec;
    }

    /**
     * Provider wire 名称（如 {@code ECDH-ES+A256GCM}）。
     */
    public String wireName() {
        return wireName;
    }

    /**
     * 匹配的收方公钥算法（{@code EC} / {@code RSA}）。
     */
    public String recipientKeyAlgorithm() {
        return recipientKeyAlgorithm;
    }

    /**
     * 是否为 ECDH-ES 套件（需要 P-256 与 {@code keyAgreement}）。
     */
    public boolean isEcdh() {
        return this == ECDH_ES_P256_HKDF_SHA256_AES256GCM;
    }

    /**
     * 按收方公钥算法推导套件；不支持时返回 {@code null}（调用方 fail-closed）。
     *
     * @param keyAlgorithm 公钥算法（{@code EC} / {@code RSA}，大小写不敏感）
     * @return 套件或 null
     */
    public static WrappingSuite forRecipientKeyAlgorithm(String keyAlgorithm) {
        if (keyAlgorithm == null || keyAlgorithm.isBlank()) {
            return null;
        }
        String normalized = keyAlgorithm.trim().toUpperCase(java.util.Locale.ROOT);
        for (WrappingSuite suite : values()) {
            if (suite.recipientKeyAlgorithm.equals(normalized)) {
                return suite;
            }
        }
        return null;
    }

    /**
     * 按 wire 名称解析套件；未知返回 null。
     *
     * @param wireName wire 名称
     * @return 套件或 null
     */
    public static WrappingSuite fromWireName(String wireName) {
        if (wireName == null || wireName.isBlank()) {
            return null;
        }
        String normalized = wireName.trim();
        for (WrappingSuite suite : values()) {
            if (suite.wireName.equalsIgnoreCase(normalized) || suite.name().equalsIgnoreCase(normalized)) {
                return suite;
            }
        }
        return null;
    }
}
