package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * KDF 参数（随 WrappedDataKey 下发，供设备端解封 / 派生时使用）
 *
 * @param salt HKDF salt
 * @param info HKDF info
 */
public record KdfParams(byte[] salt, byte[] info) implements Serializable {

    public KdfParams {
        Objects.requireNonNull(salt, "salt must not be null");
        Objects.requireNonNull(info, "info must not be null");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KdfParams that = (KdfParams) o;
        return Arrays.equals(salt, that.salt) && Arrays.equals(info, that.info);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(salt);
        result = 31 * result + Arrays.hashCode(info);
        return result;
    }

    @Override
    public String toString() {
        return "KdfParams{salt=[" + (salt == null ? 0 : salt.length) + " bytes]"
                + ", info=[" + (info == null ? 0 : info.length) + " bytes]}";
    }
}
