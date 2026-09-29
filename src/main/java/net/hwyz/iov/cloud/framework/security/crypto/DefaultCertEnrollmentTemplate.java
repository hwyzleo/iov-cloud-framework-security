package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateApplicationRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateNotReadyException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CertEnrollmentTemplate 默认实现（CR-007）
 * <p>
 * 统一封装向 PKI 提交 CSR、查询异步申请状态及获取已签发证书链。
 * 门面负责参数校验、profile 治理、幂等、鉴权、超时重试、异常归一、审计与指标；
 * PKI 继续负责 CA、审批、策略校验、签发及证书生命周期权威。
 */
public class DefaultCertEnrollmentTemplate implements CertEnrollmentTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultCertEnrollmentTemplate.class);

    private final PkiClient pkiClient;
    private final CryptoMetrics cryptoMetrics;
    private final Map<String, CertificateProfile> allowedProfiles;
    private final Map<String, String> idempotencyCache = new ConcurrentHashMap<>();
    // requestId → 申请时提交的 CSR（DER/PEM），供 getCertificate 做证书公钥 ↔ CSR 公钥一致性校验
    private final Map<String, byte[]> csrCache = new ConcurrentHashMap<>();

    public DefaultCertEnrollmentTemplate(PkiClient pkiClient,
                                                 CryptoMetrics cryptoMetrics,
                                                 List<CertificateProfile> allowedProfiles) {
        this.pkiClient = Objects.requireNonNull(pkiClient, "pkiClient must not be null");
        this.cryptoMetrics = Objects.requireNonNull(cryptoMetrics, "cryptoMetrics must not be null");
        this.allowedProfiles = new ConcurrentHashMap<>();
        if (allowedProfiles != null) {
            for (CertificateProfile profile : allowedProfiles) {
                this.allowedProfiles.put(profile.name(), profile);
            }
        }
    }

    @Override
    public CertApplyResult apply(CertApplyRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        long startTime = System.currentTimeMillis();

        try {
            // 校验 profile
            validateProfile(request.certificateProfile());

            // 校验 CSR
            validateCsr(request.pkcs10Csr());

            // 幂等检查
            String idempotencyKey = request.idempotencyKey();
            String existingRequestId = idempotencyCache.get(idempotencyKey);
            if (existingRequestId != null) {
                log.info("幂等键已存在，返回已有请求: idempotencyKey={}, requestId={}",
                        idempotencyKey, existingRequestId);
                return getStatus(existingRequestId);
            }

            // 计算 CSR 摘要用于审计
            String csrFingerprint = calculateCsrFingerprint(request.pkcs10Csr());

            // 调用 PKI 提交申请
            PkiClient.ApplyCommand command = new PkiClient.ApplyCommand(
                    request.certificateProfile().pkiProfileId(),
                    request.pkcs10Csr(),
                    request.subject().value(),
                    idempotencyKey,
                    request.context()
            );

            PkiClient.ApplyResponse response = pkiClient.submit(command);

            // 映射状态
            EnrollmentState state = mapState(response.state());

            // 缓存幂等键与 CSR（供 getCertificate 做证书公钥 ↔ CSR 公钥一致性校验）
            idempotencyCache.put(idempotencyKey, response.requestId());
            csrCache.put(response.requestId(), request.pkcs10Csr());

            long duration = System.currentTimeMillis() - startTime;
            log.info("证书申请提交成功: requestId={}, profile={}, subject={}, csrFingerprint={}, state={}, duration={}ms",
                    response.requestId(), request.certificateProfile().name(),
                    request.subject().value(), csrFingerprint, state, duration);
            cryptoMetrics.recordCertificateEnrollment(duration);

            return new CertApplyResult(response.requestId(), state, Instant.now());

        } catch (Exception e) {
            cryptoMetrics.recordError();
            long duration = System.currentTimeMillis() - startTime;
            log.error("证书申请提交失败: profile={}, subject={}, duration={}ms",
                    request.certificateProfile().name(), request.subject().value(), duration, e);
            throw e;
        }
    }

    @Override
    public CertApplyResult getStatus(String requestId) {
        Objects.requireNonNull(requestId, "requestId must not be null");
        long startTime = System.currentTimeMillis();

        try {
            PkiClient.StatusResponse response = pkiClient.getStatus(requestId);
            EnrollmentState state = mapState(response.state());

            long duration = System.currentTimeMillis() - startTime;
            log.info("查询申请状态成功: requestId={}, state={}, duration={}ms",
                    requestId, state, duration);
            cryptoMetrics.recordCertificateEnrollmentQuery(duration);

            return new CertApplyResult(requestId, state, Instant.now());

        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("查询申请状态失败: requestId={}", requestId, e);
            throw e;
        }
    }

    @Override
    public IssuedCertificate getCertificate(String requestId) {
        Objects.requireNonNull(requestId, "requestId must not be null");
        long startTime = System.currentTimeMillis();

        try {
            // 先查询状态
            CertApplyResult statusResult = getStatus(requestId);
            if (statusResult.state() != EnrollmentState.ISSUED) {
                throw new CertificateNotReadyException(
                        "Certificate not ready for requestId=" + requestId + ", current state=" + statusResult.state());
            }

            // 获取证书
            PkiClient.CertificateResponse response = pkiClient.getCertificate(requestId);

            // 申请时提交的 CSR（供公钥一致性校验；缺失时 fail-closed）
            byte[] csr = csrCache.get(requestId);

            // 解析证书链（DER 分段，按出现顺序）
            List<byte[]> certificateChain = parseCertificateChain(response.certificateChain());

            // 校验叶子证书、证书链顺序与 CSR 公钥一致性
            validateCertificateConsistency(response.leafCertificate(), certificateChain, csr);

            // 计算指纹
            String sha256Fingerprint = calculateFingerprint(response.leafCertificate());

            IssuedCertificate issuedCertificate = new IssuedCertificate(
                    response.leafCertificate(),
                    certificateChain,
                    response.serialNumber(),
                    Instant.parse(response.notBefore()),
                    Instant.parse(response.notAfter()),
                    sha256Fingerprint
            );

            long duration = System.currentTimeMillis() - startTime;
            log.info("获取证书成功: requestId={}, serialNumber={}, fingerprint={}, duration={}ms",
                    requestId, response.serialNumber(), sha256Fingerprint, duration);
            cryptoMetrics.recordCertificateEnrollmentQuery(duration);

            return issuedCertificate;

        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("获取证书失败: requestId={}", requestId, e);
            throw e;
        }
    }

    /**
     * 校验证书配置文件是否允许
     */
    private void validateProfile(CertificateProfile profile) {
        if (!allowedProfiles.containsKey(profile.name())) {
            throw new CertificateProfileNotAllowedException(
                    "Certificate profile not allowed: " + profile.name());
        }
    }

    /**
     * 校验 CSR 格式
     */
    private void validateCsr(byte[] csr) {
        if (csr == null || csr.length == 0) {
            throw new InvalidCertificateRequestException("CSR must not be null or empty");
        }
        // 基础格式校验：检查是否为 PEM 或 DER 编码
        String csrStr = new String(csr, StandardCharsets.UTF_8).trim();
        boolean isPem = csrStr.contains("-----BEGIN CERTIFICATE REQUEST-----");
        boolean isDer = csr.length > 10 && csr[0] == 0x30; // DER SEQUENCE tag

        if (!isPem && !isDer) {
            throw new InvalidCertificateRequestException(
                    "CSR must be in PEM or DER format");
        }
    }

    /**
     * 计算 CSR 摘要
     */
    private String calculateCsrFingerprint(byte[] csr) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(csr);
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidCertificateRequestException("Failed to calculate CSR fingerprint", e);
        }
    }

    /**
     * 计算证书指纹
     */
    private String calculateFingerprint(byte[] certificate) {
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

    /**
     * 解析证书链（PEM bundle 或单个 DER），返回按出现顺序排列的 DER 证书列表。
     *
     * @param certificateChainBytes PKI 返回的证书链（PEM 拼接或单个 DER）
     * @return 证书链 DER 列表（保持原始顺序）
     */
    private List<byte[]> parseCertificateChain(byte[] certificateChainBytes) {
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
     * 校验证书签发一致性（fail-closed）：
     * <ol>
     *   <li>叶子证书与证书链均可解析、链非空；</li>
     *   <li>叶子证书位于证书链首——链首即叶子，或叶子由链首签发（leaf.issuer == chain[0].subject）；</li>
     *   <li>链内顺序正确——链中每个证书的签发者 == 下一个证书的主体；</li>
     *   <li>叶子证书公钥与申请时 CSR 公钥一致（CSR 缺失时 fail-closed 拒绝，不返回证书）。</li>
     * </ol>
     * 证书链的签名验证与信任锚判定归 PKI，本门面只做结构一致性校验。
     */
    private void validateCertificateConsistency(byte[] leafCertificate,
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
     * 从 PKCS#10 CSR（PEM 或 DER）提取 SubjectPublicKeyInfo（SPKI）DER 字节。
     * <p>
     * PKCS#10 结构：CertificationRequest ::= SEQUENCE {
     *   certificationRequestInfo SEQUENCE {
     *     version INTEGER, subject Name, subjectPKInfo SubjectPublicKeyInfo, ...
     *   },
     *   signatureAlgorithm, signature }
     * 取 certificationRequestInfo（顶层 SEQUENCE 的第 1 个子元素）的第 3 个子元素即为 SPKI。
     */
    private byte[] extractCsrPublicKey(byte[] csr) {
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
    private byte[] normalizeToDer(byte[] input) {
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

    /**
     * 映射 PKI 状态到 EnrollmentState
     */
    private EnrollmentState mapState(String pkiState) {
        if (pkiState == null) {
            return EnrollmentState.PENDING;
        }
        return switch (pkiState.toUpperCase()) {
            case "PENDING", "SUBMITTED" -> EnrollmentState.PENDING;
            case "APPROVING", "APPROVAL_PENDING" -> EnrollmentState.APPROVING;
            case "PROCESSING", "IN_PROGRESS" -> EnrollmentState.PROCESSING;
            case "ISSUED", "COMPLETED", "SUCCESS" -> EnrollmentState.ISSUED;
            case "REJECTED", "DENIED" -> EnrollmentState.REJECTED;
            case "FAILED", "ERROR" -> EnrollmentState.FAILED;
            default -> EnrollmentState.PENDING;
        };
    }
}
