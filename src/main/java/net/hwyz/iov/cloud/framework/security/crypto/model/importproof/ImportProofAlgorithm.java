package net.hwyz.iov.cloud.framework.security.crypto.model.importproof;

/**
 * 导入证明算法（FW-SEC-DSN-CR-016 §3）。
 * <p>
 * 首期仅支持 {@link #ECDSA_P256_SHA256_P1363}：设备 P-256 私钥对
 * {@code SHA-256(proofInput)} 做 raw ECDSA 签名，wire 为 IEEE-P1363
 * {@code r(32-byte big-endian) || s(32-byte big-endian)}、low-S，共 64 字节。
 * <p>
 * 未知算法、DER、可变长度整数、HMAC/CMAC 或任何算法协商/fallback 均 fail-closed。
 */
public enum ImportProofAlgorithm {
    /** ECDSA P-256 / SHA-256 / P1363 low-S（64 字节） */
    ECDSA_P256_SHA256_P1363;

    /** 首期签名 wire 固定长度（字节）。 */
    public static final int SIGNATURE_LENGTH = 64;

    /** 证书/字段摘要固定长度（字节）。 */
    public static final int DIGEST_LENGTH = 32;

    /** 密钥校验值固定长度（字节）。 */
    public static final int KCV_LENGTH = 3;
}
