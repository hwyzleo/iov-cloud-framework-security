package net.hwyz.iov.cloud.framework.security.crypto.codec;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Canonical 字节编码工具（FW-SEC-DSN-CR-014 §3.2/§3.3/§8）。
 * <p>
 * 为跨端（Java Provider ↔ C++/TBOX-SEC ↔ HSM）提供<strong>确定性</strong>编码原语：
 * <ul>
 *   <li>{@link #lengthPrefixed(byte[]...)} / {@link #lengthPrefixedUtf8(String...)}：
 *       每个元素编码为 {@code int32 大端长度 || 原始字节}，字段顺序由调用方固定；</li>
 *   <li>{@link #sha256(byte[])} / {@link #hexLower(byte[])}：摘要与十六进制规范化；</li>
 *   <li>{@link #constantTimeEquals(byte[], byte[])}：恒定时间比较。</li>
 * </ul>
 * <strong>禁止</strong>使用本地默认字符集、平台换行或未定义的 JSON 序列化结果作为 KDF/AAD 输入。
 * 所有字符串统一按 UTF-8 编码。
 */
public final class CanonicalEncoding {

    private CanonicalEncoding() {
    }

    /**
     * 长度前缀编码：每段为 {@code int32 大端长度 || 原始字节}。
     *
     * @param elements 段（按给定顺序；null 视为空段）
     * @return 编码字节
     */
    public static byte[] lengthPrefixed(byte[]... elements) {
        int total = 0;
        for (byte[] element : elements) {
            total += 4 + (element == null ? 0 : element.length);
        }
        ByteBuffer buffer = ByteBuffer.allocate(total);
        for (byte[] element : elements) {
            byte[] value = element == null ? new byte[0] : element;
            buffer.putInt(value.length);
            buffer.put(value);
        }
        return buffer.array();
    }

    /**
     * 长度前缀编码（字符串按 UTF-8）。
     *
     * @param elements 字符串段（null 视为空串）
     * @return 编码字节
     */
    public static byte[] lengthPrefixedUtf8(String... elements) {
        byte[][] encoded = new byte[elements.length][];
        for (int i = 0; i < elements.length; i++) {
            encoded[i] = elements[i] == null ? new byte[0] : elements[i].getBytes(StandardCharsets.UTF_8);
        }
        return lengthPrefixed(encoded);
    }

    /**
     * SHA-256 摘要。
     *
     * @param data 输入
     * @return 32 字节摘要
     */
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data == null ? new byte[0] : data);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * 小写十六进制编码。
     *
     * @param bytes 输入
     * @return 十六进制字符串
     */
    public static String hexLower(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /**
     * 恒定时间字节比较。
     *
     * @param a 期望值
     * @param b 实际值
     * @return 相等返回 true
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        return MessageDigest.isEqual(a, b);
    }
}
