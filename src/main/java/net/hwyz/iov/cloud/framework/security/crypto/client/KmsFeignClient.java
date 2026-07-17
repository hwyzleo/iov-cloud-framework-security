package net.hwyz.iov.cloud.framework.security.crypto.client;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * KMS Feign客户端接口
 * 只有在配置了 crypto.kms.endpoint 时才会创建
 */
@FeignClient(name = "kms-service", url = "${crypto.kms.endpoint}", configuration = KmsFeignConfiguration.class)
@ConditionalOnProperty(prefix = "crypto.kms", name = "endpoint")
public interface KmsFeignClient {

    @PostMapping("/v1/transit/datakey/plaintext/{keyName}")
    FeignKmsClient.WrappedKeyResponse getActiveDataKey(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.DataKeyRequest request);

    @PostMapping("/v1/transit/datakey/plaintext/{keyName}")
    FeignKmsClient.WrappedKeyResponse getDataKeyById(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.DataKeyByIdRequest request);

    @PostMapping("/v1/transit/decrypt/{keyName}")
    FeignKmsClient.UnwrapResponse unwrap(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.UnwrapRequest request);

    @PostMapping("/v1/transit/hmac/{keyName}")
    FeignKmsClient.HmacResponse hmac(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.HmacRequest request);

    @PostMapping("/v1/transit/encrypt/{keyName}")
    FeignKmsClient.EncryptWithResponse encryptWith(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.EncryptWithRequest request);

    @PostMapping("/v1/transit/decrypt/{keyName}")
    FeignKmsClient.DecryptWithResponse decryptWith(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.DecryptWithRequest request);

    @PostMapping("/v1/transit/wrapping/wrap")
    FeignKmsClient.WrapDataKeyForDeviceResponse wrapActiveDataKeyForDevice(@RequestBody FeignKmsClient.WrapDataKeyForDeviceRequest request);

    @PostMapping("/v1/transit/session-root/{keyName}")
    FeignKmsClient.SessionRootResponse deriveSessionRoot(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.SessionRootRequest request);

    @PostMapping("/v1/transit/sign/{keyName}")
    FeignKmsClient.SignResponse signWith(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.SignRequest request);

    @PostMapping("/v1/transit/verify/{keyName}")
    FeignKmsClient.VerifyResponse verifyWith(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.VerifyRequest request);

    @PostMapping("/v1/transit/keys/{keyName}")
    FeignKmsClient.PublicKeyResponse getPublicKey(@PathVariable("keyName") String keyName, @RequestBody FeignKmsClient.PublicKeyRequest request);
}
