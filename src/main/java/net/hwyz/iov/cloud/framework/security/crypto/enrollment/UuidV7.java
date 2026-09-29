package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * UUIDv7 生成器（FW-SEC-DSN-CR-008 §5.2）
 * <p>
 * framework 生成稳定 enrollment requestId：48 位毫秒时间戳 + 版本 7 + 随机尾段。
 * 时间有序，便于结果存储按时间范围检索与运维核对。
 */
public final class UuidV7 {

    private static final SecureRandom RANDOM = new SecureRandom();

    private UuidV7() {
    }

    public static UUID random() {
        long ms = System.currentTimeMillis();
        byte[] bytes = new byte[16];

        // bytes[0..5]：48 位毫秒时间戳
        bytes[0] = (byte) (ms >>> 40);
        bytes[1] = (byte) (ms >>> 32);
        bytes[2] = (byte) (ms >>> 24);
        bytes[3] = (byte) (ms >>> 16);
        bytes[4] = (byte) (ms >>> 8);
        bytes[5] = (byte) ms;

        // bytes[6..15]：随机尾段（10 字节）
        byte[] random = new byte[10];
        RANDOM.nextBytes(random);
        System.arraycopy(random, 0, bytes, 6, 10);

        bytes[6] = (byte) ((bytes[6] & 0x0F) | 0x70);   // version 7
        bytes[8] = (byte) ((bytes[8] & 0x3F) | 0x80);   // variant 10xx

        long mostSig = 0;
        long leastSig = 0;
        for (int i = 0; i < 8; i++) {
            mostSig = (mostSig << 8) | (bytes[i] & 0xFF);
        }
        for (int i = 8; i < 16; i++) {
            leastSig = (leastSig << 8) | (bytes[i] & 0xFF);
        }
        return new UUID(mostSig, leastSig);
    }

    public static String toString(UUID uuid) {
        return uuid.toString();
    }
}
