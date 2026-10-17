package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * 派生锚点（FW-SEC-DSN-CR-013 §6）。
 * <p>
 * 承载根派生密钥的受治理锚定标识。规范化与摘要口径由 framework 拥有，业务只提供原始标识：
 * <ul>
 *   <li>VIN：{@code trim → ASCII 大写 → 长度=17 → ISO 3779 字符集（排除 I/O/Q）}，不合法 fail-closed；</li>
 *   <li>UID：{@code trim}，非空。</li>
 * </ul>
 * <strong>安全边界</strong>：{@link #value()}（规范化锚原文）只允许出现在受保护的请求体与
 * Provider 有界内存中；日志、指标、审计摘要、{@code kmsKeyRef} 与 operation 记录只允许使用
 * {@link #digest()}。
 *
 * @param type                 锚类型
 * @param normalizationVersion 规范化规则版本（防止未来规则变化产生歧义）
 * @param value                已规范化的锚原文（参与 HMAC 派生）
 */
public record KeyAnchor(AnchorType type, String normalizationVersion, String value) {

    /** VIN 规范化规则版本 */
    public static final String VIN_NORMALIZATION_VERSION = "vin-v1";
    /** UID 规范化规则版本 */
    public static final String UID_NORMALIZATION_VERSION = "uid-v1";

    private static final int VIN_LENGTH = 17;
    /** ISO 3779：大写字母 + 数字，排除 I、O、Q */
    private static final Pattern VIN_PATTERN = Pattern.compile("[A-HJ-NPR-Z0-9]{" + VIN_LENGTH + "}");

    public KeyAnchor {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(normalizationVersion, "normalizationVersion must not be null");
        Objects.requireNonNull(value, "value must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException("anchor value must not be blank");
        }
    }

    /**
     * 锚类型：VIN（车级）/ UID（设备级，即 device_sn）。
     */
    public enum AnchorType {
        VIN,
        UID
    }

    /**
     * 构造 VIN 锚：规范化（trim + 大写）并校验长度与字符集，不合法 fail-closed。
     *
     * @param vin 原始 VIN
     * @return VIN 锚
     * @throws IllegalArgumentException VIN 非空但不符合规范
     */
    public static KeyAnchor vin(String vin) {
        Objects.requireNonNull(vin, "vin must not be null");
        String normalized = vin.trim().toUpperCase();
        if (normalized.length() != VIN_LENGTH || !VIN_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException(
                    "invalid VIN: must be 17 chars from [A-HJ-NPR-Z0-9] after normalization");
        }
        return new KeyAnchor(AnchorType.VIN, VIN_NORMALIZATION_VERSION, normalized);
    }

    /**
     * 构造 UID 锚（uid 即 device_sn）：仅 trim，非空。
     *
     * @param uid 原始 uid
     * @return UID 锚
     */
    public static KeyAnchor uid(String uid) {
        Objects.requireNonNull(uid, "uid must not be null");
        String normalized = uid.trim();
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("uid must not be blank");
        }
        return new KeyAnchor(AnchorType.UID, UID_NORMALIZATION_VERSION, normalized);
    }

    /**
     * 锚摘要 {@code sha256:<64 位小写 hex>}，用于完整性比对、幂等摘要、逻辑引用与非敏感关联。
     * <p>
     * 摘要不参与密钥派生。
     *
     * @return 锚摘要
     */
    public String digest() {
        return "sha256:" + sha256Hex(value);
    }

    private static String sha256Hex(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * 仅用于日志的非敏感描述（绝不含锚原文）。
     */
    @Override
    public String toString() {
        return "KeyAnchor{type=" + type + ", normalizationVersion=" + normalizationVersion
                + ", digest=" + digest() + '}';
    }
}
