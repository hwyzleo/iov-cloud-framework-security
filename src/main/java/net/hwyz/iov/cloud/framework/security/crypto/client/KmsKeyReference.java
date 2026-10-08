package net.hwyz.iov.cloud.framework.security.crypto.client;

import java.util.Objects;

/**
 * KMS 显式密钥引用（FW-SEC-DSN-CR-009 §9）。
 *
 * @param keyId     不透明材料标识
 * @param kmsKeyRef KMS 命名密钥引用
 */
public record KmsKeyReference(String keyId, String kmsKeyRef) {

    public KmsKeyReference {
        Objects.requireNonNull(keyId, "keyId must not be null");
        Objects.requireNonNull(kmsKeyRef, "kmsKeyRef must not be null");
    }
}
