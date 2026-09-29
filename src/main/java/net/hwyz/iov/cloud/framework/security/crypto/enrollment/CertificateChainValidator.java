package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * 证书链校验器（FW-SEC-DSN-CR-008 §3.2）
 * <p>
 * 共享于 legacy-rest（结构一致性）与 step-ca（结构 + 根固定 + 签名 + 基本约束 + 有效期 + EKU/KU + SAN/Subject）。
 * 校验失败时不写入成功结果，抛出类型化异常并记录去敏审计。
 * <p>
 * 证书链的信任锚判定基于配置的根指纹（step-ca），本校验器只做确定性的结构/一致性校验。
 */
public class CertificateChainValidator {

    /**
     * 解析证书链（PEM bundle 或单个 DER），返回按出现顺序排列的 DER 证书列表。
     *
     * @param certificateChainBytes PKI 返回的证书链（PEM 拼接或单个 DER）
     * @return 证书链 DER 列表（保持原始顺序）
     */
    public List<byte[]> parseCertificateChain(byte[] certificateChainBytes) {
        if (certificateChainBytes == null || certificateChainBytes.length == 0) {
            throw new InvalidCertificateRequestException("Certificate chain must not be null or empty");
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs =
                    cf.generateCertificates(new ByteArrayInputStream(certificateChainBytes));
            if (certs == null || certs.isEmpty()) {
                throw new InvalidCertificateRequestException("Certificate chain contains no certificates");
            }
            List<byte[]> chain = new ArrayList<>(certs.size());
            for (Certificate cert : certs) {
                if (!(cert instanceof X509Certificate x509)) {
                    throw new InvalidCertificateRequestException("Certificate chain contains a non-X.509 certificate");
                }
                chain.add(x509.getEncoded());
            }
            return chain;
        } catch (CertificateException e) {
            throw new InvalidCertificateRequestException("Failed to parse certificate chain", e);
        }
    }

    /**
     * 校验证书签发一致性（fail-closed），legacy-rest 与 step-ca 共用的结构校验：
     * <ol>
     *   <li>叶子证书与证书链均可解析、链非空；</li>
     *   <li>叶子证书位于证书链首——链首即叶子，或叶子由链首签发（leaf.issuer == chain[0].subject）；</li>
     *   <li>链内顺序正确——链中每个证书的签发者 == 下一个证书的主体；</li>
     *   <li>叶子证书公钥与申请时 CSR 公钥一致（CSR 缺失时 fail-closed 拒绝，不返回证书）。</li>
     * </ol>
     */
    public void validateCertificateConsistency(byte[] leafCertificate,
                                               List<byte[]> certificateChain,
                                               byte[] csr) {
        if (leafCertificate == null || leafCertificate.length == 0) {
            throw new InvalidCertificateRequestException("Leaf certificate is empty");
        }
        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new InvalidCertificateRequestException("Certificate chain must not be empty");
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate leaf =
                    (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(leafCertificate));
            List<X509Certificate> chain = new ArrayList<>(certificateChain.size());
            for (byte[] certDer : certificateChain) {
                chain.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer)));
            }

            // 叶子位于证书链首
            X509Certificate head = chain.get(0);
            if (!MessageDigest.isEqual(leaf.getEncoded(), head.getEncoded())) {
                // 链不含叶子：要求叶子由链首签发
                if (!leaf.getIssuerX500Principal().equals(head.getSubjectX500Principal())) {
                    throw new InvalidCertificateRequestException(
                            "Leaf certificate is not at the head of the chain: "
                                    + "leaf issuer does not match the first chain certificate subject");
                }
            }

            // 链内顺序：证书 i 的签发者 == 证书 i+1 的主体
            for (int i = 0; i < chain.size() - 1; i++) {
                if (!chain.get(i).getIssuerX500Principal()
                        .equals(chain.get(i + 1).getSubjectX500Principal())) {
                    throw new InvalidCertificateRequestException(
                            "Certificate chain order is incorrect at index " + i
                                    + ": issuer does not match the next certificate subject");
                }
            }

            // 叶子证书公钥与 CSR 公钥一致
            if (csr == null || csr.length == 0) {
                throw new InvalidCertificateRequestException(
                        "CSR for the request is unavailable; cannot verify leaf public key matches CSR public key");
            }
            byte[] csrPublicKey = extractCsrPublicKey(csr);
            byte[] leafPublicKey = leaf.getPublicKey().getEncoded();
            if (!MessageDigest.isEqual(csrPublicKey, leafPublicKey)) {
                throw new InvalidCertificateRequestException(
                        "Leaf certificate public key does not match the CSR public key");
            }
        } catch (CertificateException e) {
            throw new InvalidCertificateRequestException(
                    "Failed to parse leaf certificate or chain for consistency check", e);
        }
    }

    /**
     * step-ca 签发响应完整校验（FW-SEC-DSN-CR-008 §3.2）：
     * <ol>
     *   <li>结构一致性（链首/顺序/CSR 公钥）；</li>
     *   <li>证书链签名：leaf 由 chain[0] 签发、chain[i] 由 chain[i+1] 签发；</li>
     *   <li>根固定：链尾证书指纹 == 配置根指纹；</li>
     *   <li>基本约束：CA 证书 CA:true、叶子 CA:false（存在时）；</li>
     *   <li>有效期：notAfter 不超过 now + maxValidity；</li>
     *   <li>profile 对应 EKU（如 CLIENT_AUTH）与密钥算法；</li>
     *   <li>SAN/Subject 不越权：subject/SAN 须符合 profile 的 subjectRule 前缀。</li>
     * </ol>
     */
    public void validateIssued(byte[] leafCertificate, List<byte[]> certificateChain, byte[] csr,
                               StepCaProfilePolicy policy, String rootSha256) {
        validateCertificateConsistency(leafCertificate, certificateChain, csr);

        List<X509Certificate> chain = parseAll(leafCertificate, certificateChain);
        X509Certificate leaf = chain.get(0);

        // 证书链签名验证
        verifyChainSignatures(chain);

        // 根固定
        X509Certificate root = chain.get(chain.size() - 1);
        String rootFingerprint;
        try {
            rootFingerprint = calculateFingerprint(root.getEncoded());
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new InvalidCertificateRequestException("Failed to compute root fingerprint", e);
        }
        if (!rootFingerprint.equalsIgnoreCase(normalizeFingerprint(rootSha256))) {
            throw new InvalidCertificateRequestException(
                    "Issued certificate chain root does not match pinned root fingerprint: "
                            + "expected=" + rootSha256 + " actual=" + rootFingerprint);
        }

        // 基本约束
        validateBasicConstraints(chain);

        // 有效期
        if (policy.maxValidity() != null) {
            validateValidity(leaf, policy.maxValidity());
        }

        // 密钥算法与 EKU
        validateKeyAlgorithm(leaf, policy.allowedKeyAlgorithms());
        validateRequiredEku(leaf, policy.requiredEku());

        // SAN/Subject 不越权
        if (policy.subjectRule() != null && !policy.subjectRule().isBlank()) {
            validateSubjectRule(leaf, policy.subjectRule());
        }
    }

    private void verifyChainSignatures(List<X509Certificate> chain) {
        try {
            for (int i = 0; i < chain.size() - 1; i++) {
                X509Certificate signed = chain.get(i);
                X509Certificate signer = chain.get(i + 1);
                if (!signed.getIssuerX500Principal().equals(signer.getSubjectX500Principal())) {
                    throw new InvalidCertificateRequestException(
                            "Certificate chain signature order invalid at index " + i);
                }
                signed.verify(signer.getPublicKey());
            }
        } catch (InvalidCertificateRequestException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidCertificateRequestException("Certificate chain signature verification failed", e);
        }
    }

    private void validateBasicConstraints(List<X509Certificate> chain) {
        for (int i = 1; i < chain.size(); i++) {
            X509Certificate ca = chain.get(i);
            int basicConstraints = ca.getBasicConstraints();
            if (basicConstraints < 0) {
                throw new InvalidCertificateRequestException(
                        "Chain certificate at index " + i + " is not a CA certificate");
            }
        }
        X509Certificate leaf = chain.get(0);
        int leafConstraints = leaf.getBasicConstraints();
        if (leafConstraints >= 0) {
            // 叶子不得声明 CA:true
            throw new InvalidCertificateRequestException("Leaf certificate must not be a CA certificate");
        }
    }

    private void validateValidity(X509Certificate leaf, Duration maxValidity) {
        Instant notBefore = leaf.getNotBefore().toInstant();
        Instant notAfter = leaf.getNotAfter().toInstant();
        if (!notAfter.isAfter(notBefore)) {
            throw new InvalidCertificateRequestException("Issued certificate has invalid validity period");
        }
        if (maxValidity != null && notAfter.isAfter(Instant.now().plus(maxValidity))) {
            throw new InvalidCertificateRequestException(
                    "Issued certificate validity exceeds profile max-validity: " + maxValidity);
        }
    }

    private void validateKeyAlgorithm(X509Certificate leaf, List<String> allowedKeyAlgorithms) {
        if (allowedKeyAlgorithms == null || allowedKeyAlgorithms.isEmpty()) {
            return;
        }
        String keyType = leaf.getPublicKey().getAlgorithm(); // "EC" / "RSA"
        String normalized = keyType.toUpperCase();
        for (String allowed : allowedKeyAlgorithms) {
            String upper = allowed.toUpperCase();
            if (upper.equals(normalized)
                    || (upper.equals("EC_P256") && normalized.equals("EC") && isP256(leaf))
                    || (upper.startsWith("RSA") && normalized.equals("RSA"))) {
                return;
            }
        }
        throw new InvalidCertificateRequestException(
                "Issued certificate key algorithm not allowed by profile: " + keyType);
    }

    private boolean isP256(X509Certificate leaf) {
        try {
            if (leaf.getPublicKey() instanceof java.security.interfaces.ECPublicKey ecKey) {
                String fieldSize = String.valueOf(ecKey.getParams().getCurve().getField().getFieldSize());
                return "256".equals(fieldSize);
            }
        } catch (Exception ignored) {
            // fall through
        }
        return false;
    }

    private void validateRequiredEku(X509Certificate leaf, List<String> requiredEku) {
        if (requiredEku == null || requiredEku.isEmpty()) {
            return;
        }
        try {
            List<String> present = leaf.getExtendedKeyUsage();
            for (String eku : requiredEku) {
                boolean found = false;
                for (String p : present) {
                    if (p.equals(eku) || p.endsWith("." + eku) || eku.equalsIgnoreCase(p)
                            || p.equals(EKU_OIDS.get(eku.toUpperCase()))) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    throw new InvalidCertificateRequestException(
                            "Issued certificate missing required EKU: " + eku);
                }
            }
        } catch (InvalidCertificateRequestException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidCertificateRequestException("Failed to read certificate EKU", e);
        }
    }

    private static final Map<String, String> EKU_OIDS = java.util.Map.of(
            "CLIENT_AUTH", "1.3.6.1.5.5.7.3.2",
            "SERVER_AUTH", "1.3.6.1.5.5.7.3.1",
            "CODE_SIGNING", "1.3.6.1.5.5.7.3.3",
            "EMAIL_PROTECTION", "1.3.6.1.5.5.7.3.4",
            "TIME_STAMPING", "1.3.6.1.5.5.7.3.8",
            "OCSP_SIGNING", "1.3.6.1.5.5.7.3.9");

    private void validateSubjectRule(X509Certificate leaf, String subjectRule) {
        String subject = leaf.getSubjectX500Principal().getName();
        String rule = subjectRule.toUpperCase();
        // 主体规则：CN 或 SAN 前缀匹配
        String cn = null;
        String[] parts = subject.split(",");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase().startsWith("CN=")) {
                cn = trimmed.substring(3).trim();
                break;
            }
        }
        if (cn != null && cn.toUpperCase().startsWith(rule)) {
            return;
        }
        // SAN 兜底：任意 SAN 命中前缀即放行
        try {
            Collection<List<?>> san = leaf.getSubjectAlternativeNames();
            if (san != null) {
                for (List<?> entry : san) {
                    if (entry.size() >= 2 && entry.get(1) instanceof String value
                            && value.toUpperCase().startsWith(rule)) {
                        return;
                    }
                }
            }
        } catch (Exception ignored) {
            // 解析失败按 fail-closed 处理
        }
        throw new InvalidCertificateRequestException(
                "Issued certificate subject/SAN violates profile subject rule: " + subjectRule);
    }

    /**
     * 计算证书 SHA-256 指纹（hex，小写）。
     */
    public String calculateFingerprint(byte[] certificate) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(certificate);
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidCertificateRequestException("Failed to calculate certificate fingerprint", e);
        }
    }

    private List<X509Certificate> parseAll(byte[] leafDer, List<byte[]> chainDer) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> result = new ArrayList<>(chainDer.size() + 1);
            X509Certificate leaf = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(leafDer));
            result.add(leaf);
            for (byte[] der : chainDer) {
                result.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
            }
            return result;
        } catch (CertificateException e) {
            throw new InvalidCertificateRequestException("Failed to parse certificate chain", e);
        }
    }

    /**
     * 从 PKCS#10 CSR（PEM 或 DER）提取 SubjectPublicKeyInfo（SPKI）DER 字节。
     * <p>
     * PKCS#10 结构：CertificationRequest ::= SEQUENCE {
     *   certificationRequestInfo SEQUENCE {
     *     version INTEGER, subject Name, subjectPKInfo SubjectPublicKeyInfo, ...
     *   },
     *   signatureAlgorithm, signature }
     * 取 certificationRequestInfo（顶层 SEQUENCE 的第 1 个子元素）的第 3 个子元素即为 SPKI。
     */
    public byte[] extractCsrPublicKey(byte[] csr) {
        byte[] der = normalizeToDer(csr);
        try {
            DerTlv top = readTlv(der, 0);
            if (top.tag != 0x30) {
                throw new InvalidCertificateRequestException("CSR is not a DER SEQUENCE");
            }
            DerTlv cri = readChild(der, top, 0);
            if (cri.tag != 0x30) {
                throw new InvalidCertificateRequestException("CSR certificationRequestInfo is not a SEQUENCE");
            }
            DerTlv spki = readChild(der, cri, 2);
            return Arrays.copyOfRange(der, spki.start, spki.end);
        } catch (InvalidCertificateRequestException e) {
            throw e;
        } catch (IndexOutOfBoundsException e) {
            throw new InvalidCertificateRequestException("Failed to extract public key from CSR", e);
        }
    }

    /**
     * 归一化 CSR 输入：PEM 转 DER，DER 原样返回。
     */
    public byte[] normalizeToDer(byte[] input) {
        String text = new String(input, StandardCharsets.US_ASCII).trim();
        if (text.startsWith("-----BEGIN")) {
            StringBuilder body = new StringBuilder();
            for (String line : text.split("\\r?\\n")) {
                String trimmed = line.trim();
                if (trimmed.startsWith("-----") && trimmed.endsWith("-----")) {
                    continue;
                }
                body.append(trimmed);
            }
            try {
                return Base64.getDecoder().decode(body.toString());
            } catch (IllegalArgumentException e) {
                throw new InvalidCertificateRequestException("CSR PEM base64 is malformed", e);
            }
        }
        return input;
    }

    private static String normalizeFingerprint(String fingerprint) {
        return fingerprint == null ? null : fingerprint.replace(":", "").toLowerCase();
    }

    /**
     * DER TLV 记录。
     */
    private record DerTlv(int tag, int start, int valueStart, int end) {}

    /**
     * 读取 offset 处的一个 DER TLV（仅限定长 DER）。
     */
    private DerTlv readTlv(byte[] der, int offset) {
        int pos = offset;
        int tag = der[pos] & 0xFF;
        pos++;
        if ((tag & 0x1F) == 0x1F) {
            while ((der[pos] & 0x80) != 0) {
                pos++;
            }
            pos++;
        }
        int length = der[pos] & 0xFF;
        pos++;
        if ((length & 0x80) != 0) {
            int numBytes = length & 0x7F;
            if (numBytes > 4) {
                throw new InvalidCertificateRequestException("DER length is too large");
            }
            length = 0;
            for (int i = 0; i < numBytes; i++) {
                length = (length << 8) | (der[pos] & 0xFF);
                pos++;
            }
        }
        return new DerTlv(tag, offset, pos, pos + length);
    }

    /**
     * 读取 SEQUENCE value 中的第 {@code index} 个子元素（从 0 开始）。
     */
    private DerTlv readChild(byte[] der, DerTlv parent, int index) {
        int pos = parent.valueStart;
        DerTlv child = null;
        for (int i = 0; i <= index; i++) {
            if (pos >= parent.end) {
                throw new InvalidCertificateRequestException("DER sequence has too few children");
            }
            child = readTlv(der, pos);
            pos = child.end;
        }
        return child;
    }
}
