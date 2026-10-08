package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.time.Instant;

/**
 * 业务目录描述（FW-SEC-DSN-CR-009 §4）。
 * <p>
 * 权威在 VMD；framework 仅通过 Resolver 查询并短 TTL 缓存。
 * {@code businessKeyVersion} 为 VMD 维护的业务版本（信封头携带），
 * 与 {@code kmsKeyRef} 对应的 KMS 内部版本分离（RD-009-4）。
 *
 * @param keyId             不透明材料标识
 * @param businessKeyVersion VMD 业务版本
 * @param kmsKeyRef         KMS 命名密钥引用
 * @param state             业务/密码学状态
 * @param validFrom         生效时间
 * @param validTo           失效时间
 * @param decryptUntil      DEPRECATED 可解密截止（可为 null）
 */
public record BusinessKeyDescriptor(
        String keyId,
        long businessKeyVersion,
        String kmsKeyRef,
        CryptoKeyState state,
        Instant validFrom,
        Instant validTo,
        Instant decryptUntil) implements Serializable {
}
