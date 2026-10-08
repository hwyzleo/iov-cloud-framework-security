package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.util.Objects;

/**
 * 业务密钥材料引用（FW-SEC-DSN-CR-009）。
 * <p>
 * framework 除 {@code create} 外的所有运行期业务密钥材料操作必须基于该显式引用，
 * 不允许按 deviceSn+BizType 隐式推断活跃密钥（RD-009-2 / RD-009-7）。
 *
 * @param keyId     不透明材料标识（不含 VIN/deviceSn，不可由 SDK 拼接）
 * @param kmsKeyRef KMS 侧命名密钥引用
 */
public record BusinessKeyRef(String keyId, String kmsKeyRef) implements Serializable {

    public BusinessKeyRef {
        Objects.requireNonNull(keyId, "keyId must not be null");
        Objects.requireNonNull(kmsKeyRef, "kmsKeyRef must not be null");
    }
}
