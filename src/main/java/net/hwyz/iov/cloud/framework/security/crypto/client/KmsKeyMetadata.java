package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;

import java.time.Instant;

/**
 * KMS 密钥元数据（FW-SEC-DSN-CR-009 §9）。
 *
 * @param keyId         不透明材料标识
 * @param kmsKeyRef     KMS 命名密钥引用
 * @param kmsKeyVersion KMS 内部版本
 * @param provider      KMS 提供方
 * @param algorithm     算法
 * @param keySpec       密钥规格
 * @param state         密码学状态
 * @param validFrom     生效时间
 * @param validTo       失效时间
 * @param decryptUntil  可解密截止（可为 null）
 */
public record KmsKeyMetadata(
        String keyId,
        String kmsKeyRef,
        Integer kmsKeyVersion,
        String provider,
        String algorithm,
        String keySpec,
        CryptoKeyState state,
        Instant validFrom,
        Instant validTo,
        Instant decryptUntil) {
}
