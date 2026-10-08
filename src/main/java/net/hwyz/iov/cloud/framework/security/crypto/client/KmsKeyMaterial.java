package net.hwyz.iov.cloud.framework.security.crypto.client;

import java.time.Instant;

/**
 * KMS 创建材料结果（FW-SEC-DSN-CR-009 §9）。
 *
 * @param keyId         不透明材料标识
 * @param kmsKeyRef     KMS 命名密钥引用
 * @param kmsKeyVersion KMS 内部版本（非业务版本）
 * @param provider      KMS 提供方
 * @param algorithm     算法
 * @param keySpec       密钥规格
 * @param validFrom     生效时间
 * @param validTo       失效时间
 */
public record KmsKeyMaterial(
        String keyId,
        String kmsKeyRef,
        Integer kmsKeyVersion,
        String provider,
        String algorithm,
        String keySpec,
        Instant validFrom,
        Instant validTo) {
}
