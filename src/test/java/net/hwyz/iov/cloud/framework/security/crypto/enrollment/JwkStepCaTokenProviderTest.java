package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JwkStepCaTokenProvider 单元测试（FW-SEC-DSN-CR-008 §4/§9）
 */
class JwkStepCaTokenProviderTest {

    @TempDir
    Path tempDir;

    private ECKey generateJwk() throws Exception {
        return new ECKeyGenerator(Curve.P_256)
                .keyID("openiov-kid")
                .algorithm(JWSAlgorithm.ES256)
                .generate();
    }

    private Path writeJwk(ECKey jwk) throws Exception {
        Path file = tempDir.resolve("provisioner.jwk");
        Files.writeString(file, jwk.toJSONString(), StandardCharsets.UTF_8);
        return file;
    }

    private StepCaTokenRequest request(String requestId) {
        return new StepCaTokenRequest(
                requestId,
                "openiov",
                "openiov-kid",
                URI.create("https://step-ca:9000/1.0/sign"),
                "TBOX-00000000000000000000000000000001",
                List.of("TBOX-00000000000000000000000000000001"),
                "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
                Duration.ofMinutes(5),
                Map.of()
        );
    }

    @Test
    void createToken_shouldSignWithExpectedClaims() throws Exception {
        ECKey jwk = generateJwk();
        JwkStepCaTokenProvider provider = new JwkStepCaTokenProvider(writeJwk(jwk), null, Duration.ofMinutes(5));

        String token = provider.createToken(request("req-1"));

        SignedJWT jwt = SignedJWT.parse(token);
        assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
        assertEquals("openiov-kid", jwt.getHeader().getKeyID());
        assertTrue(jwt.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(jwk.toECPublicKey())));

        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertEquals("openiov", claims.getIssuer());
        assertEquals("https://step-ca:9000/1.0/sign", claims.getAudience().get(0));
        assertEquals("TBOX-00000000000000000000000000000001", claims.getSubject());
        assertEquals("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", claims.getStringClaim("sha"));
        assertEquals(List.of("TBOX-00000000000000000000000000000001"), claims.getStringListClaim("sans"));

        // TTL：exp - iat ≈ 5 分钟
        long ttlSeconds = (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000;
        assertEquals(300, ttlSeconds, 5);

        // jti = requestId + nonce（唯一，不缓存复用）
        String jti = claims.getJWTID();
        assertNotNull(jti);
        assertTrue(jti.startsWith("req-1-"));
    }

    @Test
    void createToken_shouldNotReuseJti_acrossCalls() throws Exception {
        ECKey jwk = generateJwk();
        JwkStepCaTokenProvider provider = new JwkStepCaTokenProvider(writeJwk(jwk), null, Duration.ofMinutes(5));

        String jti1 = SignedJWT.parse(provider.createToken(request("req-1"))).getJWTClaimsSet().getJWTID();
        String jti2 = SignedJWT.parse(provider.createToken(request("req-1"))).getJWTClaimsSet().getJWTID();

        assertNotEquals(jti1, jti2, "OTT 严禁缓存复用，jti 必须唯一");
    }

    @Test
    void createToken_shouldRespectCustomTtl() throws Exception {
        ECKey jwk = generateJwk();
        JwkStepCaTokenProvider provider = new JwkStepCaTokenProvider(writeJwk(jwk), null, Duration.ofMinutes(5));

        StepCaTokenRequest request = new StepCaTokenRequest(
                "req-2", "openiov", "openiov-kid",
                URI.create("https://step-ca:9000/1.0/sign"),
                "TBOX-1", List.of("TBOX-1"), "abc",
                Duration.ofMinutes(1), Map.of());
        long ttlSeconds = (SignedJWT.parse(provider.createToken(request)).getJWTClaimsSet()
                .getExpirationTime().getTime() - new Date().getTime()) / 1000;
        assertEquals(60, ttlSeconds, 10);
    }

    @Test
    void createToken_shouldDecryptPasswordProtectedJwk() throws Exception {
        // 模拟 step-ca 发布的口令加密 JWK（go-jose JWE JSON 序列化，PBES2）
        ECKey jwk = generateJwk();
        String password = "provisioner-secret";

        com.nimbusds.jose.JWEObject jwe = new com.nimbusds.jose.JWEObject(
                new com.nimbusds.jose.JWEHeader(
                        com.nimbusds.jose.JWEAlgorithm.PBES2_HS256_A128KW,
                        com.nimbusds.jose.EncryptionMethod.A128CBC_HS256),
                new com.nimbusds.jose.Payload(jwk.toJSONString()));
        jwe.encrypt(new com.nimbusds.jose.crypto.PasswordBasedEncrypter(password, 16, 1000));

        // 转 JWE JSON 序列化（protected/encrypted_key/iv/ciphertext/tag）
        String[] parts = jwe.serialize().split("\\.");
        String json = "{\"protected\":\"" + parts[0] + "\",\"encrypted_key\":\"" + parts[1]
                + "\",\"iv\":\"" + parts[2]
                + "\",\"ciphertext\":\"" + parts[3] + "\",\"tag\":\"" + parts[4] + "\"}";
        Path keyFile = tempDir.resolve("encrypted.jwk");
        Files.writeString(keyFile, json, StandardCharsets.UTF_8);
        Path passwordFile = tempDir.resolve("password");
        Files.writeString(passwordFile, password, StandardCharsets.UTF_8);

        JwkStepCaTokenProvider provider =
                new JwkStepCaTokenProvider(keyFile, passwordFile, Duration.ofMinutes(5));

        String token = provider.createToken(request("req-3"));
        SignedJWT jwt = SignedJWT.parse(token);
        assertTrue(jwt.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(jwk.toECPublicKey())));
        assertTrue(jwt.getJWTClaimsSet().getJWTID().startsWith("req-3-"));
    }

    @Test
    void constructor_shouldFail_whenKeyFileMissing() {
        assertThrows(IllegalStateException.class,
                () -> new JwkStepCaTokenProvider(tempDir.resolve("missing.jwk"), null, Duration.ofMinutes(5)));
    }

    @Test
    void constructor_shouldFail_whenKeyFileNotAJwk() throws Exception {
        Path file = tempDir.resolve("bad.jwk");
        Files.writeString(file, "not-a-jwk", StandardCharsets.UTF_8);
        assertThrows(IllegalStateException.class,
                () -> new JwkStepCaTokenProvider(file, null, Duration.ofMinutes(5)));
    }

    @Test
    void contentConstructor_shouldSignWithPlaintextJwkContent() throws Exception {
        // 内联明文 JWK 内容（配置中心/Nacos 下发场景）
        ECKey jwk = generateJwk();
        JwkStepCaTokenProvider provider =
                new JwkStepCaTokenProvider(jwk.toJSONString(), null, Duration.ofMinutes(5));

        SignedJWT jwt = SignedJWT.parse(provider.createToken(request("req-content")));
        assertTrue(jwt.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(jwk.toECPublicKey())));
        assertTrue(jwt.getJWTClaimsSet().getJWTID().startsWith("req-content-"));
    }

    @Test
    void contentConstructor_shouldDecryptEncryptedJwkContent() throws Exception {
        // 内联口令加密 JWK 内容（密文入 Nacos，口令走环境变量）
        ECKey jwk = generateJwk();
        String password = "provisioner-secret";

        com.nimbusds.jose.JWEObject jwe = new com.nimbusds.jose.JWEObject(
                new com.nimbusds.jose.JWEHeader(
                        com.nimbusds.jose.JWEAlgorithm.PBES2_HS256_A128KW,
                        com.nimbusds.jose.EncryptionMethod.A128CBC_HS256),
                new com.nimbusds.jose.Payload(jwk.toJSONString()));
        jwe.encrypt(new com.nimbusds.jose.crypto.PasswordBasedEncrypter(password, 16, 1000));
        String[] parts = jwe.serialize().split("\\.");
        String json = "{\"protected\":\"" + parts[0] + "\",\"encrypted_key\":\"" + parts[1]
                + "\",\"iv\":\"" + parts[2]
                + "\",\"ciphertext\":\"" + parts[3] + "\",\"tag\":\"" + parts[4] + "\"}";

        JwkStepCaTokenProvider provider =
                new JwkStepCaTokenProvider(json, password, Duration.ofMinutes(5));

        SignedJWT jwt = SignedJWT.parse(provider.createToken(request("req-enc-content")));
        assertTrue(jwt.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(jwk.toECPublicKey())));
        assertTrue(jwt.getJWTClaimsSet().getJWTID().startsWith("req-enc-content-"));
    }

    @Test
    void contentConstructor_shouldFail_whenContentBlank() {
        assertThrows(IllegalStateException.class,
                () -> new JwkStepCaTokenProvider("  ", null, Duration.ofMinutes(5)));
    }
}
