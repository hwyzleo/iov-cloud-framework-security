package net.hwyz.iov.cloud.framework.security.crypto.transit;

import java.util.Arrays;

/**
 * Transit HMAC 结果（FW-SEC-DSN-CR-019 §5.2）。
 * <p>
 * HMAC 值只允许在 Provider 有界内存中流转；{@code toString()} 不回显。
 *
 * @param hmacVersion Transit 版本前缀（严格解析为 {@code v1}）
 * @param hmac        派生材料（32 字节，V2C 首期）
 * @param rootKeyName 根密钥名
 */
public record TransitHmacResult(String hmacVersion, byte[] hmac, String rootKeyName) {

    public TransitHmacResult {
        hmac = hmac == null ? null : hmac.clone();
    }

    @Override
    public byte[] hmac() {
        return hmac == null ? null : hmac.clone();
    }

    @Override
    public String toString() {
        return "TransitHmacResult{hmacVersion='" + hmacVersion + "', hmac=["
                + (hmac == null ? "null" : hmac.length + " bytes") + "], rootKeyName='"
                + rootKeyName + "'}";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof TransitHmacResult that)) {
            return false;
        }
        return java.util.Objects.equals(hmacVersion, that.hmacVersion)
                && Arrays.equals(hmac, that.hmac)
                && java.util.Objects.equals(rootKeyName, that.rootKeyName);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hash(hmacVersion, rootKeyName);
        result = 31 * result + Arrays.hashCode(hmac);
        return result;
    }
}
