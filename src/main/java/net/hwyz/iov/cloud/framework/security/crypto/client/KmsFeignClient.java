package net.hwyz.iov.cloud.framework.security.crypto.client;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
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

    // ==================== 业务密钥材料 Provider（FW-SEC-DSN-CR-011 §6 冻结 wire contract） ====================
    // 路径固定为 /v1/business-key/...；mount/api-version/capability-path 仅为启动校验的契约期望值，
    // 不参与运行时 URL 拼接或重写。禁止再使用 /v1/transit/business-key/*（虚构路径）。

    @PostMapping("/v1/business-key/keys")
    FeignKmsClient.CreateBusinessKeyResponse createBusinessKey(@RequestBody FeignKmsClient.CreateBusinessKeyRequest request);

    @PostMapping("/v1/business-key/keys/{keyId}/wrap")
    FeignKmsClient.WrapBusinessKeyResponse wrapBusinessKey(@PathVariable("keyId") String keyId,
                                                           @RequestBody FeignKmsClient.WrapBusinessKeyRequest request);

    @GetMapping("/v1/business-key/keys/{keyId}")
    FeignKmsClient.BusinessKeyMetadataResponse getBusinessKeyMetadata(@PathVariable("keyId") String keyId);

    @PostMapping("/v1/business-key/keys/{keyId}/revoke")
    FeignKmsClient.RevokeBusinessKeyResponse revokeBusinessKey(@PathVariable("keyId") String keyId,
                                                               @RequestBody FeignKmsClient.RevokeBusinessKeyRequest request);

    @GetMapping("/v1/business-key/operations/{operationId}")
    FeignKmsClient.OperationResponse getBusinessKeyOperation(@PathVariable("operationId") String operationId);

    @GetMapping("/v1/business-key/capabilities")
    FeignKmsClient.CapabilitiesResponse getBusinessKeyCapabilities();
}
