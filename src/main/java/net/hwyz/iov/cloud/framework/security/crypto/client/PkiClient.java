package net.hwyz.iov.cloud.framework.security.crypto.client;

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
     * 证书申请命令
     *
     * @param pkiProfileId   PKI profile 标识
     * @param csr            CSR（DER 或 PEM 编码）
     * @param subject        主体信息
     * @param idempotencyKey 幂等键
     * @param context        上下文信息
     */
    record ApplyCommand(
            String pkiProfileId,
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
