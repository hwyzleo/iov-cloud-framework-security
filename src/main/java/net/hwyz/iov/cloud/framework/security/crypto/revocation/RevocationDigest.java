package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 吊销查询内部摘要/序列号工具（FW-SEC-DSN-CR-010）
 * <p>
 * 仅用于不可逆摘要与 provider canonical serial；禁止用于日志输出完整证书身份。
 */
final class RevocationDigest {

    private RevocationDigest() {
    }

    /**
     * SHA-256 摘要（小写 hex）。
     */
    static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * provider canonical serial：BigInteger 的非负十六进制小写形式（无前导 0）。
     */
    static String canonicalSerial(BigInteger serial) {
        return serial.toString(16);
    }

    /**
     * 任意字节数组转小写 hex。
     */
    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
