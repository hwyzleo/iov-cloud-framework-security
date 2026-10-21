package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JwkStepCaTokenProvider 单元测试（FW-SEC-DSN-CR-008 §4/§9；FW-SEC-DSN-CR-018 §7/§8）。
 * <p>
 * 覆盖：无状态路由门面按 signerRef 选 signer、legacy 单 JWK 兼容、JWS header.kid = 有效路由 kid、
 * jti 唯一性、口令加密 JWK、以及运行时 signerRef 缺失/未知/route mismatch 的 fail-closed。
 */
class JwkStepCaTokenProviderTest {

    @TempDir
    Path tempDir;

    private static final String SUBJECT = "TBOX-00000000000000000000000000000001";
    private static final String ROOT_SHA256 =
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";

    private ECKey generateJwk(String kid) throws Exception {
        return new ECKeyGenerator(Curve.P_256)
                .keyID(kid)
                .algorithm(JWSAlgorithm.ES256)
                .generate();
    }

    private JwkSignerDescriptor signer(String signerRef, ECKey jwk, String provisioner, String kid) {
        return new JwkSignerDescriptor(signerRef, provisioner, kid,
                JwkPrivateKeyHandle.fromContent(jwk.toJSONString(), null));
    }

    private JwkStepCaTokenProvider provider(JwkSignerDescriptor... descriptors) {
        Map<String, JwkSignerDescriptor> map = new LinkedHashMap<>();
        for (JwkSignerDescriptor d : descriptors) {
            map.put(d.signerRef(), d);
        }
        return new JwkStepCaTokenProvider(new DefaultJwkSignerRegistry(map), Duration.ofMinutes(5));
    }

    private StepCaTokenRequest request(String requestId, String signerRef, String provisioner, String kid) {
        return new StepCaTokenRequest(
                requestId,
                provisioner,
                kid,
                signerRef,
                URI.create("https://step-ca:9000/1.0/sign"),
                SUBJECT,
                List.of(SUBJECT),
                ROOT_SHA256,
                Duration.ofMinutes(5),
                Map.of()
        );
    }

    private StepCaTokenRequest request(String requestId) {
        return request(requestId, StepCaProfileRouteResolver.LEGACY_SIGNER_REF, "openiov", "openiov-kid");
    }

    // ==================== legacy 单 JWK（RD-018-4） ====================

    @Test
    void createToken_shouldSignWithExpectedClaims_legacyRoute() throws Exception {
        ECKey jwk = generateJwk("openiov-kid");
        JwkStepCaTokenProvider provider = provider(
                signer(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, jwk, null, null));

        String token = provider.createToken(request("req-1"));

        SignedJWT jwt = SignedJWT.parse(token);
        assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
        // JWS header.kid = effective route kid（legacy 取自 Profile route）
        assertEquals("openiov-kid", jwt.getHeader().getKeyID());
        assertTrue(jwt.verify(new ECDSAVerifier(jwk.toECPublicKey())));

        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertEquals("openiov", claims.getIssuer());
        assertEquals("https://step-ca:9000/1.0/sign", claims.getAudience().get(0));
        assertEquals(SUBJECT, claims.getSubject());
        assertEquals(ROOT_SHA256, claims.getStringClaim("sha"));
        assertEquals(List.of(SUBJECT), claims.getStringListClaim("sans"));

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
        ECKey jwk = generateJwk("openiov-kid");
        JwkStepCaTokenProvider provider = provider(
                signer(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, jwk, null, null));

        String jti1 = SignedJWT.parse(provider.createToken(request("req-1"))).getJWTClaimsSet().getJWTID();
        String jti2 = SignedJWT.parse(provider.createToken(request("req-1"))).getJWTClaimsSet().getJWTID();

        assertNotEquals(jti1, jti2, "OTT 严禁缓存复用，jti 必须唯一");
    }

    @Test
    void createToken_shouldRespectCustomTtl() throws Exception {
        ECKey jwk = generateJwk("openiov-kid");
        JwkStepCaTokenProvider provider = provider(
                signer(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, jwk, null, null));

        StepCaTokenRequest request = new StepCaTokenRequest(
                "req-2", "openiov", "openiov-kid", StepCaProfileRouteResolver.LEGACY_SIGNER_REF,
                URI.create("https://step-ca:9000/1.0/sign"),
                "TBOX-1", List.of("TBOX-1"), "abc",
                Duration.ofMinutes(1), Map.of());
        long ttlSeconds = (SignedJWT.parse(provider.createToken(request)).getJWTClaimsSet()
                .getExpirationTime().getTime() - new Date().getTime()) / 1000;
        assertEquals(60, ttlSeconds, 10);
    }

    // ==================== 多 signer 路由（FW-SEC-DSN-CR-018 §7） ====================

    @Test
    void createToken_shouldRouteBySignerRef_selectingCorrectPrivateKey() throws Exception {
        ECKey tspKey = generateJwk("tsp-kid");
        ECKey ecdhKey = generateJwk("ecdh-kid");
        JwkStepCaTokenProvider provider = provider(
                signer("tsp-client", tspKey, "openiov", "tsp-kid"),
                signer("tbox-device-ecdh-v1", ecdhKey, "tbox-device-ecdh-v1", "ecdh-kid"));

        // Profile A（TSP）→ signer tsp-client
        String tspOtt = provider.createToken(request("req-tsp", "tsp-client", "openiov", "tsp-kid"));
        SignedJWT tspJwt = SignedJWT.parse(tspOtt);
        assertEquals("tsp-kid", tspJwt.getHeader().getKeyID(), "JWS header.kid = effective route kid");
        assertTrue(tspJwt.verify(new ECDSAVerifier(tspKey.toECPublicKey())));

        // Profile B（ECDH）→ signer tbox-device-ecdh-v1
        String ecdhOtt = provider.createToken(
                request("req-ecdh", "tbox-device-ecdh-v1", "tbox-device-ecdh-v1", "ecdh-kid"));
        SignedJWT ecdhJwt = SignedJWT.parse(ecdhOtt);
        assertEquals("ecdh-kid", ecdhJwt.getHeader().getKeyID());
        assertTrue(ecdhJwt.verify(new ECDSAVerifier(ecdhKey.toECPublicKey())));

        // signer 不串路由：TSP OTT 不能用 ECDH 公钥验签
        assertFalse(tspJwt.verify(new ECDSAVerifier(ecdhKey.toECPublicKey())));
        assertFalse(ecdhJwt.verify(new ECDSAVerifier(tspKey.toECPublicKey())));
    }

    @Test
    void createToken_shouldReject_whenSignerRefMissing() throws Exception {
        ECKey jwk = generateJwk("openiov-kid");
        JwkStepCaTokenProvider provider = provider(
                signer(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, jwk, null, null));

        StepCaTokenRequest noRef = new StepCaTokenRequest(
                "req-x", "openiov", "openiov-kid", null,
                URI.create("https://step-ca:9000/1.0/sign"), SUBJECT, List.of(SUBJECT), ROOT_SHA256,
                Duration.ofMinutes(5), Map.of());
        assertThrows(IllegalStateException.class, () -> provider.createToken(noRef),
                "signerRef 只由内部 effective route 产生，缺失必须拒绝");
    }

    @Test
    void createToken_shouldReject_whenSignerRefUnknown() throws Exception {
        ECKey jwk = generateJwk("openiov-kid");
        JwkStepCaTokenProvider provider = provider(
                signer("tsp-client", jwk, "openiov", "openiov-kid"));

        assertThrows(IllegalStateException.class,
                () -> provider.createToken(request("req-x", "missing-signer", "openiov", "openiov-kid")),
                "registry 查找失败必须在签名/HTTP 调用前拒绝（step-ca 调用次数为 0）");
    }

    @Test
    void createToken_shouldReject_whenRouteMismatch() throws Exception {
        ECKey jwk = generateJwk("openiov-kid");
        JwkStepCaTokenProvider provider = provider(
                signer("tsp-client", jwk, "openiov", "openiov-kid"));

        // 请求 kid 与 signer 绑定的 kid 冲突：不得以任一方覆盖（RD-018-5）
        assertThrows(IllegalStateException.class,
                () -> provider.createToken(request("req-x", "tsp-client", "openiov", "other-kid")));
        // provisioner 冲突
        assertThrows(IllegalStateException.class,
                () -> provider.createToken(request("req-x", "tsp-client", "other-provisioner", "openiov-kid")));
    }

    // ==================== 私钥装载 ====================

    @Test
    void createToken_shouldDecryptPasswordProtectedJwk() throws Exception {
        // 模拟 step-ca 发布的口令加密 JWK（go-jose JWE JSON 序列化，PBES2）
        ECKey jwk = generateJwk("openiov-kid");
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

        JwkStepCaTokenProvider provider = provider(
                new JwkSignerDescriptor(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, null, null,
                        JwkPrivateKeyHandle.fromFile(keyFile, passwordFile)));

        String token = provider.createToken(request("req-3"));
        SignedJWT jwt = SignedJWT.parse(token);
        assertTrue(jwt.verify(new ECDSAVerifier(jwk.toECPublicKey())));
        assertTrue(jwt.getJWTClaimsSet().getJWTID().startsWith("req-3-"));
    }

    @Test
    void constructor_shouldFail_whenKeyFileMissing() {
        assertThrows(IllegalStateException.class,
                () -> JwkPrivateKeyHandle.fromFile(tempDir.resolve("missing.jwk"), null));
    }

    @Test
    void constructor_shouldFail_whenKeyFileNotAJwk() throws Exception {
        Path file = tempDir.resolve("bad.jwk");
        Files.writeString(file, "not-a-jwk", StandardCharsets.UTF_8);
        assertThrows(IllegalStateException.class,
                () -> JwkPrivateKeyHandle.fromFile(file, null));
    }

    @Test
    void contentConstructor_shouldSignWithPlaintextJwkContent() throws Exception {
        // 内联明文 JWK 内容（配置中心/Nacos 下发场景）
        ECKey jwk = generateJwk("openiov-kid");
        JwkStepCaTokenProvider provider = provider(
                new JwkSignerDescriptor(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, null, null,
                        JwkPrivateKeyHandle.fromContent(jwk.toJSONString(), null)));

        SignedJWT jwt = SignedJWT.parse(provider.createToken(request("req-content")));
        assertTrue(jwt.verify(new ECDSAVerifier(jwk.toECPublicKey())));
        assertTrue(jwt.getJWTClaimsSet().getJWTID().startsWith("req-content-"));
    }

    @Test
    void contentConstructor_shouldDecryptEncryptedJwkContent() throws Exception {
        // 内联口令加密 JWK 内容（密文入 Nacos，口令走环境变量）
        ECKey jwk = generateJwk("openiov-kid");
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

        JwkStepCaTokenProvider provider = provider(
                new JwkSignerDescriptor(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, null, null,
                        JwkPrivateKeyHandle.fromContent(json, password)));

        SignedJWT jwt = SignedJWT.parse(provider.createToken(request("req-enc-content")));
        assertTrue(jwt.verify(new ECDSAVerifier(jwk.toECPublicKey())));
        assertTrue(jwt.getJWTClaimsSet().getJWTID().startsWith("req-enc-content-"));
    }

    @Test
    void contentConstructor_shouldFail_whenContentBlank() {
        assertThrows(IllegalStateException.class,
                () -> JwkPrivateKeyHandle.fromContent("  ", null));
    }

    @Test
    void handle_shouldRejectPublicOnlyJwk() throws Exception {
        ECKey jwk = generateJwk("openiov-kid");
        ECKey publicOnly = jwk.toPublicJWK();
        assertThrows(IllegalStateException.class,
                () -> JwkPrivateKeyHandle.fromContent(publicOnly.toJSONString(), null),
                "JWK 必须为可签名私钥（FW-SEC-DSN-CR-018 §8.5）");
    }

    @Test
    void handle_toString_mustNotLeakSecretMaterial() throws Exception {
        ECKey jwk = generateJwk("openiov-kid");
        JwkPrivateKeyHandle handle = JwkPrivateKeyHandle.fromContent(jwk.toJSONString(), null);

        String text = handle.toString();
        assertTrue(text.contains("openiov-kid"), "toString 应回显非敏感 kid 供诊断");
        assertFalse(text.contains(jwk.toJSONString()), "toString 不得回显完整 JWK JSON");
        assertFalse(text.contains(jwk.getD().toString()), "toString 不得泄漏私钥参数 d");
    }
}
