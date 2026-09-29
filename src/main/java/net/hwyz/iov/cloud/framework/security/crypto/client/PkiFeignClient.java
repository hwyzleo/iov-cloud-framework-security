package net.hwyz.iov.cloud.framework.security.crypto.client;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * PKI Feign客户端接口（legacy-rest 提供方使用）
 * <p>
 * 仅在配置了 crypto.pki.endpoint 时创建；提供方选择（step-ca / legacy-rest）由
 * CryptoAutoConfiguration 的 {@code @Bean} 条件负责，不在 {@code @FeignClient} 接口上
 * 使用 {@code @ConditionalOnExpression}（Feign 扫描阶段不解析表达式中的占位符，
 * 会导致接口条件恒不满足、bean 未注册）。
 */
@FeignClient(name = "pki-service", url = "${crypto.pki.endpoint}", configuration = PkiFeignConfiguration.class)
@ConditionalOnProperty(prefix = "crypto.pki", name = "endpoint")
public interface PkiFeignClient {

    /**
     * 提交证书申请
     *
     * @param request 申请请求
     * @return 申请响应
     */
    @PostMapping("/v1/certificates/apply")
    PkiClient.ApplyResponse submit(@RequestBody PkiClient.ApplyCommand request);

    /**
     * 查询申请状态
     *
     * @param requestId 请求 ID
     * @return 状态响应
     */
    @GetMapping("/v1/certificates/status/{requestId}")
    PkiClient.StatusResponse getStatus(@PathVariable("requestId") String requestId);

    /**
     * 获取已签发证书
     *
     * @param requestId 请求 ID
     * @return 证书响应
     */
    @GetMapping("/v1/certificates/{requestId}")
    PkiClient.CertificateResponse getCertificate(@PathVariable("requestId") String requestId);

    /**
     * 查询证书信息
     *
     * @param serialNumber 证书序列号
     * @return 证书响应
     */
    @GetMapping("/v1/certificates/serial/{serialNumber}")
    PkiClient.CertificateResponse queryCertificate(@PathVariable("serialNumber") String serialNumber);
}
