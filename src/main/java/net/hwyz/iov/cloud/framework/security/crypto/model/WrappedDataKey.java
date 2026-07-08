package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.io.Serializable;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * 活跃数据密钥·设备封装下发产物（内部对象，不落库）
 * <p>
 * 密钥明文不出 KMS，wrapped 为设备公钥/证书封装的活跃 DATA 密钥密文。
 *
 * @param wrapped   设备公钥/证书封装的活跃 DATA 密钥密文
 * @param keyId     密钥 ID
 * @param keyVersion 密钥版本
 * @param expiry    有效期
 * @param kdfParams KDF 参数（如适用）
 */
public final class WrappedDataKey implements Serializable {

    private static final long serialVersionUID = 1L;

    private byte[] wrapped;
    private String keyId;
    private int keyVersion;
    private Instant expiry;
    private KdfParams kdfParams;

    public WrappedDataKey() {
    }

    public WrappedDataKey(byte[] wrapped, String keyId, int keyVersion, Instant expiry, KdfParams kdfParams) {
        this.wrapped = wrapped;
        this.keyId = keyId;
        this.keyVersion = keyVersion;
        this.expiry = expiry;
        this.kdfParams = kdfParams;
    }

    public byte[] getWrapped() {
        return wrapped;
    }

    public void setWrapped(byte[] wrapped) {
        this.wrapped = wrapped;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public int getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(int keyVersion) {
        this.keyVersion = keyVersion;
    }

    public Instant getExpiry() {
        return expiry;
    }

    public void setExpiry(Instant expiry) {
        this.expiry = expiry;
    }

    public KdfParams getKdfParams() {
        return kdfParams;
    }

    public void setKdfParams(KdfParams kdfParams) {
        this.kdfParams = kdfParams;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WrappedDataKey that = (WrappedDataKey) o;
        return keyVersion == that.keyVersion
                && Objects.equals(keyId, that.keyId)
                && Objects.equals(expiry, that.expiry)
                && Objects.equals(kdfParams, that.kdfParams)
                && Arrays.equals(wrapped, that.wrapped);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(keyId, keyVersion, expiry, kdfParams);
        result = 31 * result + Arrays.hashCode(wrapped);
        return result;
    }

    @Override
    public String toString() {
        return "WrappedDataKey{keyId='" + keyId + "', keyVersion=" + keyVersion
                + ", expiry=" + expiry
                + ", wrapped=[" + (wrapped == null ? 0 : wrapped.length) + " bytes]"
                + ", kdfParams=" + kdfParams + "}";
    }
}
