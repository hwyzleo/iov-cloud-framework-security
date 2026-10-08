package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

/**
 * 业务密钥材料创建结果（FW-SEC-DSN-CR-009 §3）。
 * <p>
 * 含 {@code kmsKeyVersion}（KMS 提供方内部版本事实，<strong>不得充当业务版本</strong>）。
 *
 * @param keyId         不透明材料标识
 * @param kmsKeyRef     KMS 命名密钥引用
 * @param kmsKeyVersion KMS 内部版本（非业务版本 businessKeyVersion）
 * @param provider      KMS 提供方
 * @param algorithm     算法
 * @param keySpec       密钥规格
 * @param validFrom     生效时间
 * @param validTo       失效时间
 */
public record BusinessKeyMaterial(
        String keyId,
        String kmsKeyRef,
        Integer kmsKeyVersion,
        String provider,
        String algorithm,
        String keySpec,
        Instant validFrom,
        Instant validTo) implements Serializable {

    public BusinessKeyMaterial {
        Objects.requireNonNull(keyId, "keyId must not be null");
        Objects.requireNonNull(kmsKeyRef, "kmsKeyRef must not be null");
    }
}
