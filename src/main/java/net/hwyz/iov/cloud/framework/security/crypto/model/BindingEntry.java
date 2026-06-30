package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.io.Serializable;
import java.time.Instant;

/**
 * 绑定解析缓存
 */
public class BindingEntry implements Serializable {

    private static final long serialVersionUID = 1L;

    private String vin;
    private String deviceCategory;
    private String deviceSn;
    private String status;
    private Instant expireAt;

    public BindingEntry() {
    }

    public String getVin() {
        return vin;
    }

    public void setVin(String vin) {
        this.vin = vin;
    }

    public String getDeviceCategory() {
        return deviceCategory;
    }

    public void setDeviceCategory(String deviceCategory) {
        this.deviceCategory = deviceCategory;
    }

    public String getDeviceSn() {
        return deviceSn;
    }

    public void setDeviceSn(String deviceSn) {
        this.deviceSn = deviceSn;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
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
        BindingEntry that = (BindingEntry) o;
        return java.util.Objects.equals(vin, that.vin)
                && java.util.Objects.equals(deviceCategory, that.deviceCategory)
                && java.util.Objects.equals(deviceSn, that.deviceSn)
                && java.util.Objects.equals(status, that.status)
                && java.util.Objects.equals(expireAt, that.expireAt);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(vin, deviceCategory, deviceSn, status, expireAt);
    }

    @Override
    public String toString() {
        return "BindingEntry{vin='" + vin + "', deviceCategory='" + deviceCategory
                + "', deviceSn='" + deviceSn + "', status='" + status
                + "', expireAt=" + expireAt + "}";
    }
}
