package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData;
import net.hwyz.iov.cloud.framework.security.crypto.model.Recipient;

/**
 * 用收方证书 / 公钥加密门面 API（CR-006）
 * <p>
 * 以收方证书 / 公钥加密--把数据或密钥安全投递给持有对应私钥的一方（设备 SE / 手机 SE / 其他服务）。
 * 加密只用收方公钥，不涉及本地私钥 / KMS 秘密，可纯进程内完成。
 * <p>
 * 受 {@code crypto.certenc.enabled} 条件装配，仅需要「用证书加密」的消费方启用。
 * <p>
 * 算法：EC 收方走 ECIES（ECDH-ES + HKDF-SHA256 + AES-256-GCM）；
 * RSA 收方走 RSA-OAEP(SHA-256) + AES-256-GCM。
 * <p>
 * 证书信任判定 / 链校验归 PKI（{@code CertResolver} SPI），门面只做「给定合法公钥 -> 加密」。
 */
public interface CertEncryptionTemplate {

    /**
     * 混合加密任意明文：内部生成临时对称密钥做 AEAD 加密数据，再用收方公钥封装该密钥
     *
     * @param recipient  收方（公钥 / 证书 / 主体引用）
     * @param plaintext  明文
     * @return 混合加密产物
     */
    EnvelopedData encryptFor(Recipient recipient, byte[] plaintext);

    /**
     * 仅密钥封装（key transport）：把调用方持有的对称密钥 / 秘密用收方公钥封装
     *
     * @param recipient   收方
     * @param keyMaterial 调用方持有的对称密钥 / 秘密
     * @return 收方公钥封装的密钥密文
     */
    byte[] wrapKeyFor(Recipient recipient, byte[] keyMaterial);
}
