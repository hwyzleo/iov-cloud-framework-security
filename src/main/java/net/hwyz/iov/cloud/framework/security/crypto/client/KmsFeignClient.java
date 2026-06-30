package net.hwyz.iov.cloud.framework.security.crypto.client;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * KMS Feign客户端接口
 * 只有在配置了 crypto.kms.endpoint 时才会创建
 */
@FeignClient(name = "kms-service", url = "${crypto.kms.endpoint}")
@ConditionalOnProperty(prefix = "crypto.kms", name = "endpoint")
public interface KmsFeignClient {

    @PostMapping("/transit/datakey")
    FeignKmsClient.WrappedKeyResponse getActiveDataKey(@RequestBody FeignKmsClient.DataKeyRequest request);

    @PostMapping("/transit/datakey/by-id")
    FeignKmsClient.WrappedKeyResponse getDataKeyById(@RequestBody FeignKmsClient.DataKeyByIdRequest request);

    @PostMapping("/transit/decrypt")
    FeignKmsClient.UnwrapResponse unwrap(@RequestBody FeignKmsClient.UnwrapRequest request);
}
