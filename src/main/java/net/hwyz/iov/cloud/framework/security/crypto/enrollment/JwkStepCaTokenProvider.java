package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

/**
 * 基于命名 JWK signer 的无状态 OTT 路由门面（FW-SEC-DSN-CR-018 §7）。
 * <p>
 * 进程内完成 JOSE 签名，默认算法由 signer JWK 决定（如 ES256）。
 * 自身<strong>无单一私钥状态</strong>，持有不可变 {@link JwkSignerRegistry} 并按请求
 * {@code signerRef} 选择唯一 signer（RD-018-1/3）；私钥由 {@link JwkPrivateKeyHandle} 承载，
 * 不出现在日志/异常/toString 中。
 * <p>
 * token TTL 默认 5 分钟且可缩短；包含唯一 jti=requestId+nonce，严禁缓存复用 OTT。
 * <p>
 * 运行时 registry 查找失败或 route mismatch 必须在签名/HTTP 调用前拒绝
 * （FW-SEC-DSN-CR-018 §8，step-ca 调用次数为 0）。
 */
public class JwkStepCaTokenProvider implements StepCaTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwkStepCaTokenProvider.class);

    private final JwkSignerRegistry signerRegistry;
    private final Duration defaultTtl;

    public JwkStepCaTokenProvider(JwkSignerRegistry signerRegistry, Duration defaultTtl) {
        this.signerRegistry = Objects.requireNonNull(signerRegistry, "signerRegistry must not be null");
        this.defaultTtl = defaultTtl == null ? Duration.ofMinutes(5) : defaultTtl;
        log.info("初始化 JwkStepCaTokenProvider: signers={}, defaultTtl={}",
                signerRegistry.signerRefs(), this.defaultTtl);
    }

    @Override
    public String createToken(StepCaTokenRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        String signerRef = request.signerRef();
        if (signerRef == null || signerRef.isBlank()) {
            throw new IllegalStateException(
                    "step-ca OTT requires an effective signerRef; signerRef is produced only by "
                            + "the internal effective route and must not be absent (FW-SEC-DSN-CR-018 §7)");
        }
        JwkSignerDescriptor signer = signerRegistry.require(signerRef);

        // 防御纵深：signer 显式绑定的 provisioner/kid 必须与请求路由一致（HTTP 调用前拒绝）
        verifyRoute(request, signer);

        Duration ttl = request.ttl() != null ? request.ttl() : defaultTtl;
        Date now = new Date();

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(request.provisioner())
                .audience(request.audience().toString())
                .subject(request.subject())
                // 唯一 jti = requestId + nonce，严禁缓存复用 OTT
                .jwtID(request.requestId() + "-" + UUID.randomUUID())
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + ttl.toMillis()))
                .claim("sha", request.rootSha256());
        if (request.sans() != null && !request.sans().isEmpty()) {
            claims.claim("sans", request.sans());
        }
        if (request.fixedClaims() != null) {
            request.fixedClaims().forEach(claims::claim);
        }

        try {
            JWSAlgorithm alg = signer.privateKeyHandle().algorithm();
            JWSSigner jwsSigner = signer.privateKeyHandle().createSigner();
            // JWS header.kid = effective route kid（FW-SEC-DSN-CR-018 §7）
            String kid = request.kid() != null ? request.kid() : signer.privateKeyHandle().kid();
            JWSHeader header = kid != null
                    ? new JWSHeader.Builder(alg).keyID(kid).build()
                    : new JWSHeader.Builder(alg).build();
            JWSObject jws = new JWSObject(header, new Payload(claims.build().toJSONObject()));
            jws.sign(jwsSigner);
            return jws.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign step-ca OTT", e);
        }
    }

    /**
     * 运行时 route 一致性校验（FW-SEC-DSN-CR-018 §8）：signer 显式声明 provisioner/kid 时
     * 必须与请求路由一致，冲突不得覆盖。lookup 失败与 mismatch 均在签名/HTTP 调用前拒绝。
     */
    private static void verifyRoute(StepCaTokenRequest request, JwkSignerDescriptor signer) {
        if (signer.provisioner() != null && !signer.provisioner().equals(request.provisioner())) {
            throw new IllegalStateException(
                    "signer route mismatch at runtime: signerRef='" + signer.signerRef()
                            + "' provisioner='" + signer.provisioner() + "' != request provisioner='"
                            + request.provisioner() + "' (FW-SEC-DSN-CR-018 §8, fail-closed before HTTP)");
        }
        if (signer.kid() != null && !signer.kid().equals(request.kid())) {
            throw new IllegalStateException(
                    "signer route mismatch at runtime: signerRef='" + signer.signerRef()
                            + "' kid='" + signer.kid() + "' != request kid='" + request.kid()
                            + "' (FW-SEC-DSN-CR-018 §8, fail-closed before HTTP)");
        }
    }
}
