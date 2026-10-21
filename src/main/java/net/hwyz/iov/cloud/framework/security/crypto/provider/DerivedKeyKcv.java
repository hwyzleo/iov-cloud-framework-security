package net.hwyz.iov.cloud.framework.security.crypto.provider;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/**
 * KCV 计算器（FW-SEC-DSN-CR-019 §6）。
 * <p>
 * {@code KCV = first_3_bytes(SHA-256(keyMaterial))}；与 CR-014 信封与 TBOX-SEC
 * 导入一致性校验口径一致（跨端 golden vector）。
 */
public final class DerivedKeyKcv {

    /** KCV 长度（3 字节） */
    public static final int KCV_LENGTH = 3;

    private DerivedKeyKcv() {
    }

    /**
     * 计算 KCV。
     *
     * @param keyMaterial 派生材料（32 字节）
     * @return 3 字节 KCV
     */
    public static byte[] first3Sha256(byte[] keyMaterial) {
        Objects.requireNonNull(keyMaterial, "keyMaterial must not be null");
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(keyMaterial);
            return Arrays.copyOf(digest, KCV_LENGTH);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable for KCV", e);
        }
    }
}
