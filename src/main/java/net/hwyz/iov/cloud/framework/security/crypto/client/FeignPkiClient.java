package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiDependencyUnavailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Feign PKI客户端实现
 * <p>
 * 通过Feign调用PKI REST API，负责 mTLS/OAuth2/AppRole 等具体鉴权适配。
 * PKI 厂商状态与错误码在适配层映射为稳定的 framework 异常。
 */
public class FeignPkiClient implements PkiClient {

    private static final Logger log = LoggerFactory.getLogger(FeignPkiClient.class);

    private final CryptoProperties properties;
    private final PkiFeignClient pkiFeignClient;

    public FeignPkiClient(CryptoProperties properties, PkiFeignClient pkiFeignClient) {
        this.properties = properties;
        this.pkiFeignClient = pkiFeignClient;
    }

    @Override
    public ApplyResponse submit(ApplyCommand command) {
        try {
            log.debug("提交证书申请: profile={}, subject={}, idempotencyKey={}",
                    command.pkiProfileId(), command.subject(), command.idempotencyKey());
            ApplyResponse response = pkiFeignClient.submit(command);
            log.info("证书申请提交成功: requestId={}, state={}", response.requestId(), response.state());
            return response;
        } catch (Exception e) {
            log.error("证书申请提交失败: profile={}, subject={}", command.pkiProfileId(), command.subject(), e);
            throw new PkiDependencyUnavailableException("Failed to submit certificate application to PKI", e);
        }
    }

    @Override
    public StatusResponse getStatus(String requestId) {
        try {
            log.debug("查询申请状态: requestId={}", requestId);
            StatusResponse response = pkiFeignClient.getStatus(requestId);
            log.debug("查询申请状态成功: requestId={}, state={}", requestId, response.state());
            return response;
        } catch (Exception e) {
            log.error("查询申请状态失败: requestId={}", requestId, e);
            throw new PkiDependencyUnavailableException("Failed to get certificate application status from PKI", e);
        }
    }

    @Override
    public CertificateResponse getCertificate(String requestId) {
        try {
            log.debug("获取已签发证书: requestId={}", requestId);
            CertificateResponse response = pkiFeignClient.getCertificate(requestId);
            log.info("获取证书成功: requestId={}, serialNumber={}", requestId, response.serialNumber());
            return response;
        } catch (Exception e) {
            log.error("获取证书失败: requestId={}", requestId, e);
            throw new PkiDependencyUnavailableException("Failed to get certificate from PKI", e);
        }
    }

    @Override
    public CertificateResponse queryCertificate(String serialNumber) {
        try {
            log.debug("查询证书信息: serialNumber={}", serialNumber);
            CertificateResponse response = pkiFeignClient.queryCertificate(serialNumber);
            log.debug("查询证书信息成功: serialNumber={}", serialNumber);
            return response;
        } catch (Exception e) {
            log.error("查询证书信息失败: serialNumber={}", serialNumber, e);
            throw new PkiDependencyUnavailableException("Failed to query certificate from PKI", e);
        }
    }
}
