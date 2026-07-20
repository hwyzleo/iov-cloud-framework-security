package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * 已签发证书
 *
 * @param leafCertificate   叶子证书（DER 编码）
 * @param certificateChain  证书链（DER 编码列表，从叶子到根）
 * @param serialNumber      序列号
 * @param notBefore         有效期开始
 * @param notAfter          有效期结束
 * @param sha256Fingerprint SHA-256 指纹
 */
public record IssuedCertificate(

        byte[] leafCertificate,

        List<byte[]> certificateChain,

        String serialNumber,

        Instant notBefore,

        Instant notAfter,

        String sha256Fingerprint
) {

    public IssuedCertificate {
        Objects.requireNonNull(leafCertificate, "leafCertificate must not be null");
        Objects.requireNonNull(certificateChain, "certificateChain must not be null");
        Objects.requireNonNull(serialNumber, "serialNumber must not be null");
        Objects.requireNonNull(notBefore, "notBefore must not be null");
        Objects.requireNonNull(notAfter, "notAfter must not be null");
        Objects.requireNonNull(sha256Fingerprint, "sha256Fingerprint must not be null");
    }
}
