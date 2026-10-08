package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

/**
 * 业务密钥元数据（FW-SEC-DSN-CR-009）。
 * <p>
 * {@code getMetadata} 查询结果，含密码学状态；供 VMD 编排与对账使用。
 *
 * @param keyId         不透明材料标识
 * @param kmsKeyRef     KMS 命名密钥引用
 * @param kmsKeyVersion KMS 内部版本
 * @param provider      KMS 提供方
 * @param algorithm     算法
 * @param keySpec       密钥规格
 * @param state         密码学状态（ACTIVE/DEPRECATED/REVOKED/EXPIRED）
 * @param validFrom     生效时间
 * @param validTo       失效时间
 * @param decryptUntil  可解密截止（DEPRECATED 解密窗口，可为 null）
 */
public record BusinessKeyMetadata(
        String keyId,
        String kmsKeyRef,
        Integer kmsKeyVersion,
        String provider,
        String algorithm,
        String keySpec,
        CryptoKeyState state,
        Instant validFrom,
        Instant validTo,
        Instant decryptUntil) implements Serializable {

    public BusinessKeyMetadata {
        Objects.requireNonNull(keyId, "keyId must not be null");
    }
}
