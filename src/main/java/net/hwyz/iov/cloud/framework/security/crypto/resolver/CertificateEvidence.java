package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 规范化证书证据（FW-SEC-DSN-CR-012 §5）。
 * <p>
 * framework 解析并校验后的收方证书材料。{@code sha256Fingerprint} 仅用于固定与比对，
 * <b>不能</b>单独替代 Wrap 所需的 DER/SPKI；{@code spki} 是安全关键材料。
 *
 * @param certificateDer    叶子证书 DER（可能为空：仅 SPKI 场景）
 * @param spki              收方公钥 SPKI DER（可能为空：未解析出时）
 * @param serial            规范化证书序列号（十六进制小写，无前导 0；仅 SPKI 时为 null）
 * @param sha256Fingerprint SHA-256 指纹（十六进制小写，无冒号）
 * @param chain             证书链 DER（从叶子 issuer 到根，可为空）
 * @param source            证据来源
 */
public record CertificateEvidence(
        byte[] certificateDer,
        byte[] spki,
        String serial,
        String sha256Fingerprint,
        List<byte[]> chain,
        EvidenceSource source
) implements Serializable {

    public CertificateEvidence {
        Objects.requireNonNull(source, "source must not be null");
        if (certificateDer == null && spki == null) {
            throw new IllegalArgumentException("certificateDer and spki must not both be null");
        }
        certificateDer = certificateDer == null ? null : certificateDer.clone();
        spki = spki == null ? null : spki.clone();
        chain = chain == null ? List.of() : copyChain(chain);
    }

    public boolean hasLeafDer() {
        return certificateDer != null && certificateDer.length > 0;
    }

    public boolean hasSpki() {
        return spki != null && spki.length > 0;
    }

    private static List<byte[]> copyChain(List<byte[]> chain) {
        List<byte[]> copy = new ArrayList<>(chain.size());
        for (byte[] der : chain) {
            copy.add(der == null ? null : der.clone());
        }
        return List.copyOf(copy);
    }
}
