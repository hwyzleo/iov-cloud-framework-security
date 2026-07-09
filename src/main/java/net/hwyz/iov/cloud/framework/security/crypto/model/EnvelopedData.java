package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * 证书/公钥混合加密产物
 * <p>
 * EC 收方：{@code alg=ECIES_AES_256_GCM}，{@code ephemeralPubOrParams} 为临时公钥 SPKI DER；
 * RSA 收方：{@code alg=RSA_OAEP_AES_256_GCM}，{@code ephemeralPubOrParams} 为 GCM IV/nonce。
 * <p>
 * {@code ciphertext} 为 AEAD 密文，{@code wrappedKey} 为收方公钥封装的临时对称密钥。
 *
 * @param ciphertext          AEAD 密文（含 tag）
 * @param wrappedKey          收方公钥封装的临时对称密钥
 * @param alg                 加密算法标识
 * @param ephemeralPubOrParams 临时公钥（EC）或参数（RSA IV/nonce）
 */
public record EnvelopedData(byte[] ciphertext, byte[] wrappedKey, EncAlg alg, byte[] ephemeralPubOrParams)
        implements java.io.Serializable {

    public EnvelopedData {
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");
        Objects.requireNonNull(wrappedKey, "wrappedKey must not be null");
        Objects.requireNonNull(alg, "alg must not be null");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EnvelopedData that = (EnvelopedData) o;
        return alg == that.alg
                && Arrays.equals(ciphertext, that.ciphertext)
                && Arrays.equals(wrappedKey, that.wrappedKey)
                && Arrays.equals(ephemeralPubOrParams, that.ephemeralPubOrParams);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(alg);
        result = 31 * result + Arrays.hashCode(ciphertext);
        result = 31 * result + Arrays.hashCode(wrappedKey);
        result = 31 * result + Arrays.hashCode(ephemeralPubOrParams);
        return result;
    }

    @Override
    public String toString() {
        return "EnvelopedData{alg=" + alg
                + ", ciphertext=[" + ciphertext.length + " bytes]"
                + ", wrappedKey=[" + wrappedKey.length + " bytes]"
                + ", ephemeralPubOrParams=[" + (ephemeralPubOrParams != null ? ephemeralPubOrParams.length : 0) + " bytes]}";
    }

    /**
     * 证书加密算法标识
     */
    public enum EncAlg {
        /** ECIES: ECDH-ES + HKDF-SHA256 + AES-256-GCM */
        ECIES_AES_256_GCM,
        /** RSA-OAEP(SHA-256) + AES-256-GCM */
        RSA_OAEP_AES_256_GCM
    }
}
