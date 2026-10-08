package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * 密钥材料策略（FW-SEC-DSN-CR-009）。
 * <p>
 * 描述要创建的业务密钥材料的密码学属性；不承载业务目录/用途/版本信息。
 *
 * @param algorithm  算法（如 AES_256_GCM / AES_256）
 * @param keySpec    密钥规格 / 长度（如 256）
 * @param validity   材料有效期（可选，默认由 KMS 侧决定）
 * @param parameters 提供方参数（可选，不含秘密）
 */
public record KeyMaterialPolicy(
        String algorithm,
        String keySpec,
        Duration validity,
        Map<String, String> parameters) implements Serializable {

    public KeyMaterialPolicy {
        Objects.requireNonNull(algorithm, "algorithm must not be null");
    }

    public static KeyMaterialPolicy of(String algorithm, String keySpec) {
        return new KeyMaterialPolicy(algorithm, keySpec, null, null);
    }
}
