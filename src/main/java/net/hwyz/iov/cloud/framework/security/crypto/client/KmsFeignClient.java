package net.hwyz.iov.cloud.framework.security.crypto.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * KMS Feign客户端接口
 * 通过Nacos服务发现调用 kms-service
 */
@FeignClient(name = "kms-service")
public interface KmsFeignClient {

    @PostMapping("/transit/datakey")
    FeignKmsClient.WrappedKeyResponse getActiveDataKey(@RequestBody FeignKmsClient.DataKeyRequest request);

    @PostMapping("/transit/datakey/by-id")
    FeignKmsClient.WrappedKeyResponse getDataKeyById(@RequestBody FeignKmsClient.DataKeyByIdRequest request);

    @PostMapping("/transit/decrypt")
    FeignKmsClient.UnwrapResponse unwrap(@RequestBody FeignKmsClient.UnwrapRequest request);

    @PostMapping("/transit/hmac")
    FeignKmsClient.HmacResponse hmac(@RequestBody FeignKmsClient.HmacRequest request);

    @PostMapping("/transit/encrypt")
    FeignKmsClient.EncryptWithResponse encryptWith(@RequestBody FeignKmsClient.EncryptWithRequest request);

    @PostMapping("/transit/decrypt-named")
    FeignKmsClient.DecryptWithResponse decryptWith(@RequestBody FeignKmsClient.DecryptWithRequest request);

    @PostMapping("/transit/datakey/wrap-for-device")
    FeignKmsClient.WrapDataKeyForDeviceResponse wrapActiveDataKeyForDevice(@RequestBody FeignKmsClient.WrapDataKeyForDeviceRequest request);

    @PostMapping("/transit/session-root")
    FeignKmsClient.SessionRootResponse deriveSessionRoot(@RequestBody FeignKmsClient.SessionRootRequest request);

    @PostMapping("/transit/sign")
    FeignKmsClient.SignResponse signWith(@RequestBody FeignKmsClient.SignRequest request);

    @PostMapping("/transit/verify")
    FeignKmsClient.VerifyResponse verifyWith(@RequestBody FeignKmsClient.VerifyRequest request);

    @PostMapping("/transit/public-key")
    FeignKmsClient.PublicKeyResponse getPublicKey(@RequestBody FeignKmsClient.PublicKeyRequest request);
}
