package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;

/**
 * 证书注册门面 API（CR-007）
 * <p>
 * 统一封装向 PKI 提交 CSR、查询异步申请状态及获取已签发证书链。
 * 门面负责参数校验、profile 治理、幂等、鉴权、超时重试、异常归一、审计与指标；
 * PKI 继续负责 CA、审批、策略校验、签发及证书生命周期权威。
 * <p>
 * 受 {@code crypto.pki.endpoint} 条件装配，仅证书注册消费方启用。
 * <p>
 * API 不接收私钥。CSR 由调用方、KMS/HSM 或设备 SE 生成；私钥始终留在原安全边界内。
 */
public interface CertEnrollmentTemplate {

    /**
     * 提交证书申请
     * <p>
     * 提交 PKCS#10 CSR 并返回稳定 {@code requestId}；PKI 若同步签发可直接返回
     * {@code ISSUED}，否则返回中间状态。
     *
     * @param request 证书申请请求
     * @return 证书申请结果
     */
    CertApplyResult apply(CertApplyRequest request);

    /**
     * 查询申请状态
     *
     * @param requestId 请求 ID
     * @return 申请结果（包含当前状态）
     */
    CertApplyResult getStatus(String requestId);

    /**
     * 获取已签发证书
     * <p>
     * 仅在 {@code ISSUED} 状态返回证书材料，其他状态抛类型化异常或返回明确的未就绪语义。
     *
     * @param requestId 请求 ID
     * @return 已签发证书
     */
    IssuedCertificate getCertificate(String requestId);
}
