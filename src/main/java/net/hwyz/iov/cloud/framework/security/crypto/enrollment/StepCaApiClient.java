package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import java.util.List;
import java.util.Objects;

/**
 * step-ca 原生 API 客户端 SPI（FW-SEC-DSN-CR-008 §3）
 * <p>
 * 仅覆盖 framework 需要的端点：POST /sign（版本化部署对应 /1.0/sign）与 GET /root/{sha}。
 * step-ca 不存在 framework 当前自研的 /v1/certificates/* 资源，也没有通用按序列号
 * 读取已签发证书的 CA 路由。
 */
public interface StepCaApiClient {

    /**
     * 同步签发：POST {endpoint}/1.0/sign。
     *
     * @param request 签发请求（CSR PEM + OTT + 可选时间约束）
     * @return 签发响应（统一为确定顺序 leaf → intermediate → root）
     */
    StepCaSignResponse sign(StepCaSignRequest request);

    /**
     * 获取根证书：GET {endpoint}/root/{sha256Fingerprint}。
     *
     * @param sha256Fingerprint 根 SHA-256 指纹
     * @return 根证书响应
     */
    StepCaRootResponse getRoot(String sha256Fingerprint);

    /**
     * step-ca /1.0/sign 请求。
     *
     * @param csr       PEM PKCS#10 CSR
     * @param ott       一次性令牌（JWT）
     * @param notBefore 可选；受 profile 限制
     * @param notAfter  可选；受 profile 限制
     */
    record StepCaSignRequest(String csr, String ott, String notBefore, String notAfter) {

        public StepCaSignRequest {
            Objects.requireNonNull(csr, "csr must not be null");
            Objects.requireNonNull(ott, "ott must not be null");
        }
    }

    /**
     * step-ca /1.0/sign 响应（已归一化）。
     *
     * @param leafPem   叶子证书 PEM
     * @param chainPem  证书链 PEM（确定顺序 intermediate → root，不含 leaf）
     */
    record StepCaSignResponse(String leafPem, List<String> chainPem) {

        public StepCaSignResponse {
            Objects.requireNonNull(leafPem, "leafPem must not be null");
            Objects.requireNonNull(chainPem, "chainPem must not be null");
        }
    }

    /**
     * step-ca /root/{sha} 响应。
     *
     * @param rootPem 根证书 PEM
     */
    record StepCaRootResponse(String rootPem) {

        public StepCaRootResponse {
            Objects.requireNonNull(rootPem, "rootPem must not be null");
        }
    }
}
