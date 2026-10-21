package net.hwyz.iov.cloud.framework.security.crypto.config;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.JwkSignerRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaProfileRouteResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * step-ca 多 JWK signer registry 工厂单元测试（FW-SEC-DSN-CR-018 §5/§8/§10）。
 * <p>
 * 覆盖：legacy 兼容（RD-018-4）、多 signer 构建、signerRef 保留名/格式校验（§8.1）、
 * 私钥来源冲突（§8.4）、配置 kid 与 JWK kid 一致性（§8.5）等 fail-closed 场景。
 * Profile→signer 路由解析负向用例见 {@code StepCaProfileRouteResolverTest}。
 */
class StepCaJwkSignerRegistryFactoryTest {

    private ECKey generateKey(String kid) throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(kid).algorithm(JWSAlgorithm.ES256).generate();
    }

    private CryptoProperties.Pki.StepCa stepCa() {
        CryptoProperties properties = new CryptoProperties();
        properties.getPki().getStepCa().setTokenProvider("jwk");
        return properties.getPki().getStepCa();
    }

    private CryptoProperties.Pki.JwkSignerProperties signerConfig(String provisioner, String kid,
                                                                  String jwkJson) {
        CryptoProperties.Pki.JwkSignerProperties signer = new CryptoProperties.Pki.JwkSignerProperties();
        signer.setProvisioner(provisioner);
        signer.setKid(kid);
        signer.setPrivateKeyContent(jwkJson);
        return signer;
    }

    @Test
    void create_legacyOnly_registersLegacySigner() throws Exception {
        // 阶段 A：仅 legacy 单 JWK → 映射为保留 __legacy__（RD-018-4）
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().setPrivateKeyContent(generateKey("kid-1").toJSONString());

        JwkSignerRegistry registry = StepCaJwkSignerRegistryFactory.create(stepCa);

        assertTrue(registry.signerRefs().contains(StepCaProfileRouteResolver.LEGACY_SIGNER_REF));
        assertEquals(null, registry.require(StepCaProfileRouteResolver.LEGACY_SIGNER_REF).provisioner(),
                "legacy signer 不绑定 provisioner/kid（route 取自 Profile）");
    }

    @Test
    void create_multiSigner_registersAllSigners() throws Exception {
        // 阶段 B/C：两个命名 signer 各自持钥
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().getSigners().put("tsp-client",
                signerConfig("openiov", "tsp-kid", generateKey("tsp-kid").toJSONString()));
        stepCa.getJwk().getSigners().put("tbox-device-ecdh-v1",
                signerConfig("tbox-device-ecdh-v1", "ecdh-kid", generateKey("ecdh-kid").toJSONString()));

        JwkSignerRegistry registry = StepCaJwkSignerRegistryFactory.create(stepCa);

        assertEquals(Set.of("tsp-client", "tbox-device-ecdh-v1"), registry.signerRefs());
        assertEquals("openiov", registry.require("tsp-client").provisioner());
        assertEquals("ecdh-kid", registry.require("tbox-device-ecdh-v1").kid());
    }

    @Test
    void create_shouldReject_reservedSignerRef() throws Exception {
        // §8.1：__legacy__ 为内部保留引用
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().getSigners().put("__legacy__",
                signerConfig("openiov", "kid-1", generateKey("kid-1").toJSONString()));

        assertThrows(IllegalStateException.class, () -> StepCaJwkSignerRegistryFactory.create(stepCa));
    }

    @Test
    void create_shouldReject_invalidSignerRefFormat() throws Exception {
        // §8.1：含空格 / __ 前缀 的 signerRef 拒绝
        for (String badRef : new String[]{"tsp client", "__reserved"}) {
            CryptoProperties.Pki.StepCa stepCa = stepCa();
            stepCa.getJwk().getSigners().put(badRef,
                    signerConfig("openiov", "kid-1", generateKey("kid-1").toJSONString()));
            assertThrows(IllegalStateException.class,
                    () -> StepCaJwkSignerRegistryFactory.create(stepCa),
                    "signerRef='" + badRef + "' 应被拒绝");
        }
    }

    @Test
    void create_shouldReject_privateKeySourceConflict() throws Exception {
        // §8.4：file 与 content 同时配置 → 私钥来源冲突
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().setPrivateKeyFile("/run/secrets/legacy.jwk");
        stepCa.getJwk().setPrivateKeyContent(generateKey("kid-1").toJSONString());

        assertThrows(IllegalStateException.class, () -> StepCaJwkSignerRegistryFactory.create(stepCa));
    }

    @Test
    void create_shouldReject_signerKidConflictWithJwk() throws Exception {
        // §8.5：signer 配置 kid 与 JWK 自身 kid 不一致
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().getSigners().put("tsp-client",
                signerConfig("openiov", "configured-kid", generateKey("jwk-kid").toJSONString()));

        assertThrows(IllegalStateException.class, () -> StepCaJwkSignerRegistryFactory.create(stepCa));
    }

    @Test
    void create_shouldReject_invalidJwkContent_withSignerContext() throws Exception {
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().getSigners().put("tsp-client",
                signerConfig("openiov", "tsp-kid", generateKey("tsp-kid").toJSONString()));
        CryptoProperties.Pki.JwkSignerProperties bad = signerConfig("tbox-device-ecdh-v1", "ecdh-kid",
                "{\"kid\":\"ecdh-kid\",\"crv\":\"P-256\",\"use\":\"sig\"}"); // 缺 kty
        stepCa.getJwk().getSigners().put("tbox-device-ecdh-v1", bad);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> StepCaJwkSignerRegistryFactory.create(stepCa));

        assertTrue(ex.getMessage().contains("tbox-device-ecdh-v1"),
                "报错必须定位具体 signer: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("Failed to parse provisioner JWK"), ex.getMessage());
    }

    /**
     * 生成 go-jose JWE JSON 序列化（protected/encrypted_key/iv/ciphertext/tag）的口令加密 JWK。
     */
    private String encryptJwk(String plaintextJwkJson, String password) throws Exception {
        JWEObject jwe = new JWEObject(
                new JWEHeader(JWEAlgorithm.PBES2_HS256_A128KW, EncryptionMethod.A128CBC_HS256),
                new Payload(plaintextJwkJson));
        jwe.encrypt(new PasswordBasedEncrypter(password, 16, 1000));
        String[] parts = jwe.serialize().split("\\.");
        return "{\"protected\":\"" + parts[0] + "\",\"encrypted_key\":\"" + parts[1]
                + "\",\"iv\":\"" + parts[2]
                + "\",\"ciphertext\":\"" + parts[3] + "\",\"tag\":\"" + parts[4] + "\"}";
    }

    @Test
    void create_shouldSupport_inlineContentWithPasswordFile(@TempDir Path tempDir) throws Exception {
        // §5.2：内联 content 来源同样支持 password-file（Secret 挂载口令）
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        String password = "provisioner-secret";
        Path passwordFile = tempDir.resolve("password");
        Files.writeString(passwordFile, password, StandardCharsets.UTF_8);
        CryptoProperties.Pki.JwkSignerProperties signer =
                signerConfig("tbox-device-ecdh-v1", "ecdh-kid", encryptJwk(generateKey("ecdh-kid").toJSONString(), password));
        signer.setPasswordFile(passwordFile.toString());
        stepCa.getJwk().getSigners().put("tbox-device-ecdh-v1", signer);

        JwkSignerRegistry registry = StepCaJwkSignerRegistryFactory.create(stepCa);

        assertEquals(Set.of("tbox-device-ecdh-v1"), registry.signerRefs());
    }

    @Test
    void create_shouldReject_unreadablePasswordFileForInlineContent(@TempDir Path tempDir) throws Exception {
        // password-file 配置但不可读 → fail-closed 且指明 signer
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        CryptoProperties.Pki.JwkSignerProperties signer =
                signerConfig("tbox-device-ecdh-v1", "ecdh-kid",
                        encryptJwk(generateKey("ecdh-kid").toJSONString(), "x"));
        signer.setPasswordFile(tempDir.resolve("missing-password").toString());
        stepCa.getJwk().getSigners().put("tbox-device-ecdh-v1", signer);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> StepCaJwkSignerRegistryFactory.create(stepCa));

        assertTrue(ex.getMessage().contains("tbox-device-ecdh-v1"), ex.getMessage());
        assertTrue(ex.getMessage().contains("password file is not readable"), ex.getMessage());
    }

    @Test
    void create_shouldReject_unsupportedTokenProvider() {
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.setTokenProvider("nimbus");
        assertThrows(IllegalStateException.class, () -> StepCaJwkSignerRegistryFactory.create(stepCa));
    }
}
