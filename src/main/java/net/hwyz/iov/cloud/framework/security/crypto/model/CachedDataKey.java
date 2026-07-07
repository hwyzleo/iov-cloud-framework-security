package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.io.Serializable;
import java.time.Instant;
import java.util.Arrays;

/**
 * 缓存项
 */
public class CachedDataKey implements Serializable {

    private static final long serialVersionUID = 1L;

    private String keyId;
    private int keyVersion;
    private transient byte[] dekPlaintext;
    private BizType bizType;
    private String deviceSn;
    private Instant expireAt;

    public CachedDataKey() {
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

    public byte[] getDekPlaintext() {
        return dekPlaintext;
    }

    public void setDekPlaintext(byte[] dekPlaintext) {
        this.dekPlaintext = dekPlaintext;
    }

    public BizType getBizType() {
        return bizType;
    }

    public void setBizType(BizType bizType) {
        this.bizType = bizType;
    }

    public String getDeviceSn() {
        return deviceSn;
    }

    public void setDeviceSn(String deviceSn) {
        this.deviceSn = deviceSn;
    }

    public Instant getExpireAt() {
        return expireAt;
    }

    public void setExpireAt(Instant expireAt) {
        this.expireAt = expireAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CachedDataKey that = (CachedDataKey) o;
        return keyVersion == that.keyVersion
                && java.util.Objects.equals(keyId, that.keyId)
                && Arrays.equals(dekPlaintext, that.dekPlaintext)
                && java.util.Objects.equals(bizType, that.bizType)
                && java.util.Objects.equals(deviceSn, that.deviceSn)
                && java.util.Objects.equals(expireAt, that.expireAt);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hash(keyId, keyVersion, bizType, deviceSn, expireAt);
        result = 31 * result + Arrays.hashCode(dekPlaintext);
        return result;
    }

    @Override
    public String toString() {
        return "CachedDataKey{keyId='" + keyId + "', keyVersion=" + keyVersion
                + ", bizType=" + bizType + ", deviceSn='" + deviceSn
                + "', expireAt=" + expireAt + "}";
    }
}
