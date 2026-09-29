package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * step-ca 一次性令牌（OTT）请求（FW-SEC-DSN-CR-008 §4.1）
 *
 * @param requestId    enrollment requestId（并入 jti，保证一次性）
 * @param provisioner  provisioner 名
 * @param kid          provisioner JWK 的 kid
 * @param audience     令牌 audience（精确 sign URL）
 * @param subject      证书主体
 * @param sans         允许的 SAN 列表（约束 SAN 不越权）
 * @param rootSha256   根指纹（以 sha claim 约束信任根）
 * @param ttl          令牌有效期
 * @param fixedClaims  额外固定声明（仅 framework 白名单字段）
 */
public record StepCaTokenRequest(
        String requestId,
        String provisioner,
        String kid,
        URI audience,
        String subject,
        List<String> sans,
        String rootSha256,
        Duration ttl,
        Map<String, Object> fixedClaims
) {

    public StepCaTokenRequest {
        Objects.requireNonNull(requestId, "requestId must not be null");
        Objects.requireNonNull(audience, "audience must not be null");
        // ttl 可为空：由提供者使用默认 TTL（如 JwkStepCaTokenProvider 默认 5 分钟）
    }
}
