package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateStatusConfigurationException;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Objects;

/**
 * PKI 客户端接口（CR-007）
 * <p>
 * 统一封装与 PKI 服务的交互，包括证书注册、查询、获取等操作。
 * 类似于 {@link KmsClient} 对 KMS 的抽象，{@code PkiClient} 对 PKI 服务进行抽象，
 * 隔离具体 PKI 厂商协议与错误码。
 * <p>
 * 默认实现通过 PKI REST API 调用，负责 mTLS/OAuth2/AppRole 等具体鉴权适配；
 * 业务门面不暴露传输协议。PKI 厂商状态与错误码在适配层映射为稳定的
 * {@code EnrollmentState} 和 framework 异常。
 * <p>
 * 如后续更换 PKI 提供方，仅替换实现，不影响业务 API。
 */
public interface PkiClient {

    /**
     * 提交证书申请
     * <p>
     * 提交 PKCS#10 CSR 到 PKI，返回申请结果。
     *
     * @param command 申请命令
     * @return 申请响应
     */
    ApplyResponse submit(ApplyCommand command);

    /**
     * 查询申请状态
     *
     * @param requestId 请求 ID
     * @return 状态响应
     */
    StatusResponse getStatus(String requestId);

    /**
     * 获取已签发证书
     * <p>
     * 仅在证书已签发时返回证书材料，其他状态应抛出异常。
     *
     * @param requestId 请求 ID
     * @return 证书响应
     */
    CertificateResponse getCertificate(String requestId);

    /**
     * 查询证书信息
     * <p>
     * 根据证书序列号或指纹查询证书信息。
     *
     * @param serialNumber 证书序列号
     * @return 证书响应
     */
    CertificateResponse queryCertificate(String serialNumber);

    /**
     * 是否自行管理 enrollment 结果存储（FW-SEC-DSN-CR-008 §5.1）
     * <p>
     * step-ca 为同步签发且无 requestId/status/certificate 三段式契约，由
     * {@code StepCaPkiClient} 在 submit 内原子写入结果存储并自行维护状态；
     * legacy-rest 沿用 PKI 自研 REST 契约，由门面在 submit 后回写结果存储。
     * 门面据此决定结果存储的写入时机，避免双写。
     *
     * @return true 表示该实现自行管理结果存储
     */
    default boolean managesResultStore() {
        return false;
    }

    /**
     * 查询证书状态/吊销状态（FW-SEC-DSN-CR-010 §2）。
     * <p>
     * 默认实现抛出 {@link CertificateStatusConfigurationException}：新能力由
     * {@code crypto.pki.revocation.enabled} 条件装配，默认关闭。关闭时调用本方法必须得到明确的
     * configuration-disabled 异常，<b>不得</b>返回 {@code GOOD}。
     * <p>
     * 启用时由 provider 实现（legacy-rest / step-ca）委托 framework 的证书状态检查器执行：
     * 标准 OCSP 优先、CRL 受控后备，统一 TLS/超时/重试/类型化异常。
     *
     * @param query 证书状态查询（serial 必填，可选指纹与调用方携带的叶子证书 DER）
     * @return 统一状态结果（GOOD/REVOKED/UNKNOWN）
     */
    default CertificateStatusResult checkCertificateStatus(CertificateStatusQuery query) {
        throw new CertificateStatusConfigurationException(
                "Certificate status query is disabled: set crypto.pki.revocation.enabled=true "
                        + "to enable OCSP/CRL revocation checking (FW-SEC-DSN-CR-010 §5/§8)");
    }

    /**
     * 将序列号归一化为 provider canonical form：去冒号/空白、去 {@code 0x} 前缀、小写、去前导 0。
     *
     * @param serial 原始序列号（十六进制，可含冒号分隔）
     * @return 规范化序列号；{@code null} 或非法时抛出 {@link IllegalArgumentException}
     */
    static String canonicalSerial(String serial) {
        if (serial == null) {
            throw new IllegalArgumentException("Certificate serial must not be null");
        }
        String cleaned = serial.trim()
                .replace(":", "")
                .replace(" ", "")
                .replace("\t", "");
        if (cleaned.regionMatches(true, 0, "0x", 0, 2)) {
            cleaned = cleaned.substring(2);
        }
        if (cleaned.isEmpty()) {
            throw new IllegalArgumentException("Certificate serial must not be blank");
        }
        try {
            return new BigInteger(cleaned, 16).toString(16);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Certificate serial is not a valid hex value", e);
        }
    }

    /**
     * 归一化 SHA-256 指纹：去冒号/空白、小写。
     */
    static String normalizeFingerprint(String fingerprint) {
        if (fingerprint == null) {
            return null;
        }
        String normalized = fingerprint.replace(":", "").replace(" ", "").toLowerCase();
        return normalized.isBlank() ? null : normalized;
    }

    /**
     * 证书状态查询输入（FW-SEC-DSN-CR-010 §2，按决策 RD-010-7 扩展叶子证书）。
     *
     * @param serial            证书序列号（必填，十六进制，自动规范化为 provider canonical form）
     * @param sha256Fingerprint 可选 SHA-256 指纹（存在时必须与已解析证书一致）
     * @param leafCertificateDer 可选：调用方本次实际用于 mTLS 的叶子证书（DER）。
     *                           step-ca 等无 serial 目录查询能力的 Provider 必须提供。
     *                           framework 不持久化、不写日志。
     * @param decisionAt        裁决时刻（缺省为调用时刻）
     */
    record CertificateStatusQuery(
            String serial,
            String sha256Fingerprint,
            byte[] leafCertificateDer,
            Instant decisionAt) {

        public CertificateStatusQuery {
            serial = canonicalSerial(serial);
            sha256Fingerprint = normalizeFingerprint(sha256Fingerprint);
            leafCertificateDer = leafCertificateDer == null ? null : leafCertificateDer.clone();
            decisionAt = decisionAt == null ? Instant.now() : decisionAt;
        }

        /**
         * 便捷构造：不携带叶子证书。
         */
        public CertificateStatusQuery(String serial, String sha256Fingerprint, Instant decisionAt) {
            this(serial, sha256Fingerprint, null, decisionAt);
        }

        /**
         * 防御性拷贝：叶子证书为敏感材料，不外泄内部数组引用。
         */
        @Override
        public byte[] leafCertificateDer() {
            return leafCertificateDer == null ? null : leafCertificateDer.clone();
        }
    }

    /**
     * 证书状态查询结果（FW-SEC-DSN-CR-010 §2）。
     *
     * @param revocationState 吊销状态（GOOD/REVOKED/UNKNOWN）；UNKNOWN 不得映射为 GOOD
     * @param notBefore       证书有效期开始
     * @param notAfter        证书有效期结束（供业务方冗余兜底）
     * @param thisUpdate      状态响应 thisUpdate
     * @param nextUpdate      状态响应 nextUpdate（可能为空）
     * @param source          来源（OCSP/CRL）
     * @param checkedAt       framework 检查完成时刻
     */
    record CertificateStatusResult(
            RevocationState revocationState,
            Instant notBefore,
            Instant notAfter,
            Instant thisUpdate,
            Instant nextUpdate,
            RevocationSource source,
            Instant checkedAt) {

        public CertificateStatusResult {
            Objects.requireNonNull(revocationState, "revocationState must not be null");
            Objects.requireNonNull(notBefore, "notBefore must not be null");
            Objects.requireNonNull(notAfter, "notAfter must not be null");
            Objects.requireNonNull(source, "source must not be null");
            Objects.requireNonNull(checkedAt, "checkedAt must not be null");
        }
    }

    /**
     * 吊销状态（一等状态，UNKNOWN 不等于 GOOD）。
     */
    enum RevocationState {
        GOOD,
        REVOKED,
        UNKNOWN
    }

    /**
     * 吊销状态来源。
     */
    enum RevocationSource {
        OCSP,
        CRL
    }

    /**
     * 证书申请命令
     *
     * @param requestId      framework 生成的稳定请求 ID（UUIDv7，FW-SEC-DSN-CR-008 §5.2）
     * @param pkiProfileId   PKI profile 标识
     * @param profileName    framework 治理的 CertificateProfile 名称（step-ca policy 映射用）
     * @param csr            CSR（DER 或 PEM 编码）
     * @param subject        主体信息
     * @param idempotencyKey 幂等键
     * @param context        上下文信息
     */
    record ApplyCommand(
            String requestId,
            String pkiProfileId,
            String profileName,
            byte[] csr,
            String subject,
            String idempotencyKey,
            java.util.Map<String, String> context
    ) {}

    /**
     * 申请响应
     *
     * @param requestId 请求 ID
     * @param state     状态（PENDING/APPROVING/PROCESSING/ISSUED/REJECTED/FAILED）
     * @param message   消息
     */
    record ApplyResponse(
            String requestId,
            String state,
            String message
    ) {}

    /**
     * 状态响应
     *
     * @param requestId 请求 ID
     * @param state     状态
     * @param message   消息
     */
    record StatusResponse(
            String requestId,
            String state,
            String message
    ) {}

    /**
     * 证书响应
     *
     * @param requestId       请求 ID
     * @param leafCertificate 叶子证书（DER 编码）
     * @param certificateChain 证书链（DER 编码）
     * @param serialNumber    序列号
     * @param notBefore       有效期开始（ISO 8601）
     * @param notAfter        有效期结束（ISO 8601）
     */
    record CertificateResponse(
            String requestId,
            byte[] leafCertificate,
            byte[] certificateChain,
            String serialNumber,
            String notBefore,
            String notAfter
    ) {}
}
