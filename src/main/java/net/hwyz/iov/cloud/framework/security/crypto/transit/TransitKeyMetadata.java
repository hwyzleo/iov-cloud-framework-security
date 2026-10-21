package net.hwyz.iov.cloud.framework.security.crypto.transit;

/**
 * Transit 根密钥元数据（FW-SEC-DSN-CR-019 §5.2/§10）。
 * <p>
 * 用于 readiness 根类型/版本/不可导出校验与信封 {@code rootKeyVersion} 取值。
 * 非敏感对象，可进入日志/指标。
 *
 * @param name                 根密钥名
 * @param type                 Transit 密钥类型（如 {@code aes256-gcm96}）
 * @param exportable           是否可导出（DERIVED_ROOT 必须为 false）
 * @param derived              是否 derived 密钥
 * @param currentKeyVersion    当前密钥版本（信封 rootKeyVersion 取值）
 * @param latestVersion        最新版本
 * @param minDecryptionVersion 最小解密版本
 */
public record TransitKeyMetadata(
        String name,
        String type,
        boolean exportable,
        boolean derived,
        long currentKeyVersion,
        long latestVersion,
        long minDecryptionVersion) {

    public boolean isAesHmacCompatible() {
        if (type == null) {
            return false;
        }
        String normalized = type.trim().toLowerCase(java.util.Locale.ROOT);
        // OpenBao Transit 支持 aes128-gcm96/aes256-gcm96/chacha20-poly1305/aes256-gcm96-hmac-sha256 等
        return normalized.contains("aes") || normalized.contains("hmac");
    }
}
