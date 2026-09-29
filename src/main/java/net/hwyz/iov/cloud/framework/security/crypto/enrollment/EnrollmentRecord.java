package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * 证书注册交付记录（FW-SEC-DSN-CR-008 §5.1）
 * <p>
 * 至少保存 requestId、caller、idempotencyKey、CSR SHA-256、profile、状态、证书序列号、
 * leaf/chain（DER）、有效期、指纹、创建/更新时间及去敏错误摘要。
 * <p>
 * CSR 为公开材料（主体 + 公钥 + 自签名），为支撑门面 getCertificate 的公钥一致性校验而留存；
 * 证书材料非私钥，但仍按安全数据管理（静态加密、最小权限、TTL 不短于业务补偿窗口、禁止输出普通日志）。
 * 该记录是 enrollment 交付记录，不取代 PKI 的 CA/吊销/生命周期权威。
 */
public record EnrollmentRecord(

        String requestId,

        String caller,

        String idempotencyKey,

        byte[] csr,

        String csrSha256,

        String profileName,

        EnrollmentState state,

        String serialNumber,

        byte[] leafCertificate,

        List<byte[]> certificateChain,

        String notBefore,

        String notAfter,

        String sha256Fingerprint,

        String errorSummary,

        Instant createdAt,

        Instant updatedAt
) {

    public EnrollmentRecord {
        Objects.requireNonNull(requestId, "requestId must not be null");
        Objects.requireNonNull(caller, "caller must not be null");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey must not be null");
        Objects.requireNonNull(csr, "csr must not be null");
        Objects.requireNonNull(csrSha256, "csrSha256 must not be null");
        Objects.requireNonNull(profileName, "profileName must not be null");
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(updatedAt, "updatedAt must not be null");
    }

    /**
     * 返回同记录、仅更新状态的副本。
     */
    public EnrollmentRecord withState(EnrollmentState newState) {
        return new EnrollmentRecord(requestId, caller, idempotencyKey, csr, csrSha256, profileName,
                newState, serialNumber, leafCertificate, certificateChain, notBefore, notAfter,
                sha256Fingerprint, errorSummary, createdAt, Instant.now());
    }

    /**
     * 返回同记录、仅更新去敏错误摘要的副本。
     */
    public EnrollmentRecord withErrorSummary(String newErrorSummary) {
        return new EnrollmentRecord(requestId, caller, idempotencyKey, csr, csrSha256, profileName,
                state, serialNumber, leafCertificate, certificateChain, notBefore, notAfter,
                sha256Fingerprint, newErrorSummary, createdAt, Instant.now());
    }

    /**
     * 计算 CSR 的 SHA-256 十六进制摘要（用于幂等比对与审计）。
     */
    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * 计算证书 DER 的 SHA-256 十六进制指纹。
     */
    public static String fingerprintHex(byte[] der) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(digest.digest(der));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Base64（无填充）编码，用于记录内二进制字段的存储/传输。
     */
    public static String toBase64(byte[] data) {
        return Base64.getEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] fromBase64(String value) {
        return Base64.getDecoder().decode(value);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     * 便捷：从字符串计算摘要。
     */
    public static String sha256Hex(String value) {
        return sha256Hex(value.getBytes(StandardCharsets.UTF_8));
    }
}
