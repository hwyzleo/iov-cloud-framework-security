package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.io.Serializable;
import java.util.Arrays;

/**
 * KMS返回的包装密钥
 */
public class WrappedKey implements Serializable {

    private static final long serialVersionUID = 1L;

    private String keyId;
    private int keyVersion;
    private byte[] wrappedDek;

    public WrappedKey() {
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

    public byte[] getWrappedDek() {
        return wrappedDek;
    }

    public void setWrappedDek(byte[] wrappedDek) {
        this.wrappedDek = wrappedDek;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WrappedKey that = (WrappedKey) o;
        return keyVersion == that.keyVersion
                && java.util.Objects.equals(keyId, that.keyId)
                && Arrays.equals(wrappedDek, that.wrappedDek);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hash(keyId, keyVersion);
        result = 31 * result + Arrays.hashCode(wrappedDek);
        return result;
    }

    @Override
    public String toString() {
        return "WrappedKey{keyId='" + keyId + "', keyVersion=" + keyVersion
                + ", wrappedDek=" + Arrays.toString(wrappedDek) + "}";
    }
}
