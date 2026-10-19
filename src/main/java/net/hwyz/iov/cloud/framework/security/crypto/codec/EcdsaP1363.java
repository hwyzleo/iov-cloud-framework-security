package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.exception.ImportProofRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofAlgorithm;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofRejectReason;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

/**
 * ECDSA P-256 / SHA-256 / IEEE-P1363 low-S 编解码与验签（FW-SEC-DSN-CR-016 §5）。
 * <p>
 * 首期唯一签名 wire 为 {@code r(32-byte big-endian) || s(32-byte big-endian)}、
 * {@code 1 <= r < n}、{@code 1 <= s <= n/2}（low-S）。
 * <p>
 * JCA {@code SHA256withECDSA} 通常接受 DER 签名，故内部将 P1363 r/s <strong>严格</strong>编码为
 * 最短正整数 DER SEQUENCE 后调用 JCA；该 DER 仅用于 Provider 适配，
 * <strong>不</strong>是 wire、日志或持久化事实源。
 * <p>
 * 哈希语义固定为 {@code SHA-256(proofInput)}；使用 {@code SHA256withECDSA} 时直接输入
 * {@code proofInput}，<strong>禁止</strong>先对 proofInput 哈希后再调用 {@code SHA256withECDSA}。
 */
public final class EcdsaP1363 {

    /**
     * NIST P-256（secp256r1）曲线阶 {@code n}。
     */
    public static final BigInteger P256_ORDER_N = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    /**
     * {@code n / 2}，用于 low-S 上界校验。
     */
    public static final BigInteger P256_HALF_N = P256_ORDER_N.shiftRight(1);

    private static final String JCA_ALGORITHM = "SHA256withECDSA";

    private EcdsaP1363() {
    }

    /**
     * P1363 标量对。
     */
    public record Scalars(BigInteger r, BigInteger s) {
    }

    /**
     * 解析并校验 P1363 签名（长度、r/s 范围与 low-S）。
     *
     * @param proof 64 字节 P1363 签名
     * @return 校验通过的标量对
     * @throws ImportProofRejectedException 长度非法（INVALID_LENGTH）、标量越界
     *                                       （INVALID_SCALAR）或 high-S（HIGH_S）
     */
    public static Scalars parse(byte[] proof) {
        if (proof == null || proof.length != ImportProofAlgorithm.SIGNATURE_LENGTH) {
            throw new ImportProofRejectedException(ImportProofRejectReason.INVALID_LENGTH,
                    "import proof must be exactly " + ImportProofAlgorithm.SIGNATURE_LENGTH
                            + " bytes (P1363 r||s)");
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(proof, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(proof, 32, 64));
        if (r.signum() <= 0 || r.compareTo(P256_ORDER_N) >= 0
                || s.signum() <= 0 || s.compareTo(P256_ORDER_N) >= 0) {
            throw new ImportProofRejectedException(ImportProofRejectReason.INVALID_SCALAR,
                    "import proof scalar out of range (require 1 <= r,s < n)");
        }
        if (s.compareTo(P256_HALF_N) > 0) {
            throw new ImportProofRejectedException(ImportProofRejectReason.HIGH_S,
                    "import proof signature is high-S (require s <= n/2)");
        }
        return new Scalars(r, s);
    }

    /**
     * 将 P1363 标量对严格编码为最短正整数 DER SEQUENCE（内部 JCA 适配，非 wire 事实源）。
     *
     * @param scalars 标量对
     * @return DER 编码签名
     */
    public static byte[] encodeDer(Scalars scalars) {
        byte[] r = toMinimalPositiveDerInteger(scalars.r());
        byte[] s = toMinimalPositiveDerInteger(scalars.s());
        int contentLength = r.length + s.length;
        byte[] out = new byte[2 + contentLength];
        out[0] = 0x30;
        out[1] = (byte) contentLength;
        System.arraycopy(r, 0, out, 2, r.length);
        System.arraycopy(s, 0, out, 2 + r.length, s.length);
        return out;
    }

    /**
     * 将 DER ECDSA 签名反向解析为 64 字节 P1363，并归一化为 low-S
     * （{@code s &gt; n/2} 时取 {@code n - s}）。
     * <p>
     * 仅支持 P-256 的 DER SEQUENCE(&#123;INTEGER r, INTEGER s&#125;)，短形式长度。
     * 供 capability 自检与测试向量往返使用；<strong>不</strong>作为 wire 事实源。
     *
     * @param der DER 签名
     * @return 64 字节 P1363 low-S 签名
     * @throws IllegalArgumentException DER 非法
     */
    public static byte[] derToP1363(byte[] der) {
        if (der == null || der.length < 8 || (der[0] & 0xFF) != 0x30) {
            throw new IllegalArgumentException("invalid DER ECDSA signature");
        }
        int seqLen = der[1] & 0xFF;
        if (seqLen >= 0x80 || der.length != 2 + seqLen) {
            throw new IllegalArgumentException("unsupported DER ECDSA signature length");
        }
        int offset = 2;
        BigInteger[] values = new BigInteger[2];
        for (int i = 0; i < 2; i++) {
            if (offset + 2 > der.length || (der[offset] & 0xFF) != 0x02) {
                throw new IllegalArgumentException("invalid DER ECDSA integer");
            }
            int len = der[offset + 1] & 0xFF;
            offset += 2;
            if (len == 0 || offset + len > der.length) {
                throw new IllegalArgumentException("invalid DER ECDSA integer length");
            }
            values[i] = new BigInteger(Arrays.copyOfRange(der, offset, offset + len));
            offset += len;
        }
        if (offset != der.length) {
            throw new IllegalArgumentException("trailing bytes in DER ECDSA signature");
        }
        BigInteger s = values[1];
        if (s.compareTo(P256_HALF_N) > 0) {
            s = P256_ORDER_N.subtract(s);
        }
        return concat(toFixed32(values[0]), toFixed32(s));
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] magnitude = value.toByteArray();
        byte[] out = new byte[32];
        if (magnitude.length > 32) {
            System.arraycopy(magnitude, magnitude.length - 32, out, 0, 32);
        } else {
            System.arraycopy(magnitude, 0, out, 32 - magnitude.length, magnitude.length);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * 使用 P-256 公钥执行 ECDSA-SHA256 验签。
     *
     * @param publicKey P-256 公钥
     * @param proofInput canonical proofInput（<strong>不</strong>预先哈希）
     * @param proof      64 字节 P1363 low-S 签名
     * @return 验签通过返回 true；签名不适配返回 false
     * @throws ImportProofRejectedException 签名编码非法（长度/标量/high-S）
     */
    public static boolean verify(PublicKey publicKey, byte[] proofInput, byte[] proof) {
        Scalars scalars = parse(proof);
        byte[] der = encodeDer(scalars);
        try {
            Signature signature = Signature.getInstance(JCA_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(proofInput);
            return signature.verify(der);
        } catch (ImportProofRejectedException e) {
            throw e;
        } catch (Exception e) {
            // Provider 异常（如 unsupported key）：确定性失败，绝不降级为放行
            throw new ImportProofRejectedException(ImportProofRejectReason.SIGNATURE_INVALID,
                    "ECDSA verification failed: " + e.getClass().getSimpleName(), e);
        }
    }

    /**
     * 判定 ECDSA P-256/SHA-256 Provider 是否可用（用于 capability/readiness 自检）。
     *
     * @return 可用返回 true
     */
    public static boolean providerAvailable() {
        try {
            Signature.getInstance(JCA_ALGORITHM);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] toMinimalPositiveDerInteger(BigInteger value) {
        byte[] magnitude = value.toByteArray();
        // BigInteger.toByteArray() 已是最短二补码；正数若最高位为 1 会带前导 0x00，恰为 DER 所需。
        if (magnitude.length > 1 && magnitude[0] == 0x00 && (magnitude[1] & 0x80) == 0) {
            magnitude = Arrays.copyOfRange(magnitude, 1, magnitude.length);
        }
        byte[] out = new byte[2 + magnitude.length];
        out[0] = 0x02;
        out[1] = (byte) magnitude.length;
        System.arraycopy(magnitude, 0, out, 2, magnitude.length);
        return out;
    }
}
