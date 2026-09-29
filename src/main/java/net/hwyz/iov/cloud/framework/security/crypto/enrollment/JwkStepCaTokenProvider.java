package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

/**
 * 基于本地 JWK 的 OTT 提供者（FW-SEC-DSN-CR-008 §4.2）
 * <p>
 * 进程内完成 JOSE 签名，默认算法由 provisioner JWK 决定（如 ES256）。
 * 私钥来源仅支持：只读 Secret 文件（明文 JWK 或 step-ca 发布的口令加密 JWK）；
 * 不支持把明文私钥直接写入 application.yml / Nacos。
 * <p>
 * token TTL 默认 5 分钟且可缩短；包含唯一 jti=requestId+nonce，严禁缓存复用 OTT。
 */
public class JwkStepCaTokenProvider implements StepCaTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwkStepCaTokenProvider.class);

    private final JWK jwk;
    private final Duration defaultTtl;

    public JwkStepCaTokenProvider(Path privateKeyFile, Path passwordFile, Duration defaultTtl) {
        this.jwk = loadJwk(Objects.requireNonNull(privateKeyFile, "privateKeyFile must not be null"), passwordFile);
        this.defaultTtl = defaultTtl == null ? Duration.ofMinutes(5) : defaultTtl;
        log.info("初始化 JwkStepCaTokenProvider: kid={}, kty={}, alg={}",
                jwk.getKeyID(), jwk.getKeyType(), jwk.getAlgorithm());
    }

    @Override
    public String createToken(StepCaTokenRequest request) {
        Objects.requireNonNull(request, "request must not be null");
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
            JWSAlgorithm alg = resolveAlgorithm();
            JWSSigner signer = createSigner();
            String kid = request.kid() != null ? request.kid() : jwk.getKeyID();
            JWSHeader header = kid != null
                    ? new JWSHeader.Builder(alg).keyID(kid).build()
                    : new JWSHeader.Builder(alg).build();
            JWSObject jws = new JWSObject(header, new Payload(claims.build().toJSONObject()));
            jws.sign(signer);
            return jws.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign step-ca OTT", e);
        }
    }

    private JWK loadJwk(Path privateKeyFile, Path passwordFile) {
        String json;
        try {
            json = Files.readString(privateKeyFile, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read provisioner JWK file: " + privateKeyFile, e);
        }
        if (passwordFile != null && Files.isReadable(passwordFile)) {
            try {
                String password = Files.readString(passwordFile, StandardCharsets.UTF_8).trim();
                JWK decrypted = decryptEncryptedJwk(json, password);
                log.info("解密 step-ca 加密 provisioner JWK 成功");
                return decrypted;
            } catch (Exception e) {
                log.warn("加密 JWK 解密失败，尝试按明文 JWK 解析: {}", e.getMessage());
            }
        }
        try {
            return JWK.parse(json);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse provisioner JWK: " + privateKeyFile, e);
        }
    }

    /**
     * 解密 step-ca 发布的口令加密 JWK，支持两种形态：
     * <ol>
     *   <li>step-ca ca.json 中的 provisioner JWK：公开 JWK 字段 + {@code encryptedKey}（JWE compact，PBES2）；</li>
     *   <li>独立 JWE JSON 序列化（protected/encrypted_key/iv/ciphertext/tag）。</li>
     * </ol>
     */
    private JWK decryptEncryptedJwk(String json, String password) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.readTree(json);

        // 形态 1：step-ca ca.json 内嵌 provisioner（public JWK + encryptedKey JWE compact）
        if (node.has("encryptedKey") && node.get("encryptedKey").isTextual()) {
            JWEObject jwe = JWEObject.parse(node.get("encryptedKey").asText());
            jwe.decrypt(new PasswordBasedDecrypter(password));
            JsonNode privatePart = mapper.readTree(jwe.getPayload().toString());
            com.fasterxml.jackson.databind.node.ObjectNode merged =
                    (com.fasterxml.jackson.databind.node.ObjectNode) node.deepCopy();
            merged.remove("encryptedKey");
            // 合并私钥字段（d、x、y 等）
            privatePart.fields().forEachRemaining(e -> merged.set(e.getKey(), e.getValue()));
            return JWK.parse(mapper.writeValueAsString(merged));
        }

        // 形态 2：独立 JWE JSON 序列化
        if (node.has("protected") && node.has("ciphertext") && node.has("iv") && node.has("tag")) {
            Base64URL protectedHeader = new Base64URL(node.get("protected").asText());
            Base64URL encryptedKey = node.has("encrypted_key") && !node.get("encrypted_key").isNull()
                    ? new Base64URL(node.get("encrypted_key").asText()) : null;
            Base64URL iv = new Base64URL(node.get("iv").asText());
            Base64URL ciphertext = new Base64URL(node.get("ciphertext").asText());
            Base64URL tag = new Base64URL(node.get("tag").asText());
            JWEObject jwe = new JWEObject(protectedHeader, encryptedKey, iv, ciphertext, tag);
            jwe.decrypt(new PasswordBasedDecrypter(password));
            return JWK.parse(jwe.getPayload().toString());
        }

        throw new IllegalArgumentException("Not a supported encrypted JWK format");
    }

    private JWSAlgorithm resolveAlgorithm() {
        if (jwk.getAlgorithm() instanceof JWSAlgorithm jwsAlg) {
            return jwsAlg;
        }
        if (jwk instanceof ECKey ecKey) {
            return switch (ecKey.getCurve().getName()) {
                case "P-256" -> JWSAlgorithm.ES256;
                case "P-384" -> JWSAlgorithm.ES384;
                case "P-521" -> JWSAlgorithm.ES512;
                default -> JWSAlgorithm.ES256;
            };
        }
        if (jwk instanceof RSAKey) {
            return JWSAlgorithm.RS256;
        }
        throw new IllegalStateException("Unsupported JWK type for OTT signing: " + jwk.getKeyType());
    }

    private JWSSigner createSigner() throws JOSEException {
        if (jwk instanceof ECKey ecKey) {
            return new ECDSASigner(ecKey.toECPrivateKey());
        }
        if (jwk instanceof RSAKey rsaKey) {
            return new RSASSASigner(rsaKey.toRSAPrivateKey());
        }
        throw new IllegalStateException("Unsupported JWK type for OTT signing: " + jwk.getKeyType());
    }
}
