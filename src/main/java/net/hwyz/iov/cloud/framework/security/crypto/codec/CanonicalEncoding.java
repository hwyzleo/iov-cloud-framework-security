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
 *   <li>{@link #uint64be(long)} / {@link #unsignedVarint(long)}：导入证明 proofInput 的跨语言数值编码
 *       （FW-SEC-DSN-CR-016 §3 / TBOX-SEC-DSN-CR-020 §7.3）；</li>
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
     * 小写十六进制解码（FW-SEC-DSN-CR-015 §4.1：将信封指纹还原为 32 字节证书摘要）。
     * <p>
     * 允许可选的 {@code 0x}/{@code 0X} 前缀；长度必须为偶数，且仅接受十六进制字符。
     * 输入为 {@code null} 返回 {@code null}；空串返回空数组。非法输入抛
     * {@link IllegalArgumentException}（调用方 fail-closed）。
     *
     * @param hex 十六进制字符串
     * @return 解码字节
     */
    public static byte[] hexDecode(String hex) {
        if (hex == null) {
            return null;
        }
        String normalized = hex.trim();
        if (normalized.startsWith("0x") || normalized.startsWith("0X")) {
            normalized = normalized.substring(2);
        }
        if (normalized.isEmpty()) {
            return new byte[0];
        }
        if (normalized.length() % 2 != 0) {
            throw new IllegalArgumentException("hex length must be even: " + normalized.length());
        }
        int len = normalized.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            int hi = Character.digit(normalized.charAt(i * 2), 16);
            int lo = Character.digit(normalized.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("hex contains non-hex characters");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /**
     * 固定 8 字节无符号大端编码（FW-SEC-DSN-CR-016 §3 / TBOX-SEC-DSN-CR-020 §7.3）。
     * <p>
     * 仅用于明确要求 {@code uint64be} 的 canonical 输入（如导入证明的 {@code businessKeyVersion}）。
     * 调用方须保证语义范围为 {@code 1..2^63-1}（首字节最高位为 0）。
     *
     * @param value 非负长整型
     * @return 8 字节大端编码
     */
    public static byte[] uint64be(long value) {
        if (value < 0) {
            throw new IllegalArgumentException("uint64be value must be non-negative: " + value);
        }
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
    }

    /**
     * 无符号 LEB128 varint 编码（FW-SEC-DSN-CR-016 §3 / TBOX-SEC-DSN-CR-020 §7.3）。
     * <p>
     * 首期用于 purpose 等小范围受治理枚举数值（如 {@code 1}→{@code 01}、{@code 2}→{@code 02}）。
     *
     * @param value 非负长整型
     * @return varint 编码字节
     */
    public static byte[] unsignedVarint(long value) {
        if (value < 0) {
            throw new IllegalArgumentException("unsignedVarint value must be non-negative: " + value);
        }
        byte[] buffer = new byte[10];
        int index = 0;
        long remaining = value;
        do {
            byte current = (byte) (remaining & 0x7F);
            remaining >>>= 7;
            if (remaining != 0) {
                current |= (byte) 0x80;
            }
            buffer[index++] = current;
        } while (remaining != 0);
        byte[] out = new byte[index];
        System.arraycopy(buffer, 0, out, 0, index);
        return out;
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
