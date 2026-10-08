package net.hwyz.iov.cloud.framework.security.crypto.client;

import java.time.Instant;
import java.util.Map;

/**
 * KMS 封装结果（FW-SEC-DSN-CR-009 §9）。
 * <p>
 * 瞬时产物，不落库、不进日志或事件。
 *
 * @param wrapped       收方封装密文
 * @param keyId         不透明材料标识
 * @param kmsKeyVersion KMS 内部版本
 * @param algorithm     封装算法
 * @param expiry        有效期
 * @param parameters    附加参数（不含秘密）
 */
public record KmsWrappedKey(
        byte[] wrapped,
        String keyId,
        Integer kmsKeyVersion,
        String algorithm,
        Instant expiry,
        Map<String, String> parameters) {
}
