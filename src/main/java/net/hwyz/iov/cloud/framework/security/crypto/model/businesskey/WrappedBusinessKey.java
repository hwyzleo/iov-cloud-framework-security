package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;

/**
 * 瞬时封装结果（FW-SEC-DSN-CR-009 §3）。
 * <p>
 * Wrapped Key <strong>不落库、不进日志或事件</strong>，使用后即释放。
 * {@code kmsKeyVersion} 为 KMS 内部版本，不得充当业务版本。
 *
 * @param wrapped       收方封装后的密文
 * @param keyId         不透明材料标识
 * @param kmsKeyVersion KMS 内部版本
 * @param algorithm     封装算法
 * @param expiry        有效期
 * @param parameters    附加参数（不含秘密）
 */
public record WrappedBusinessKey(
        byte[] wrapped,
        String keyId,
        Integer kmsKeyVersion,
        String algorithm,
        Instant expiry,
        Map<String, String> parameters) implements Serializable {
}
