package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

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
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 私钥句柄装载失败可诊断性测试（FW-SEC-DSN-CR-018 §8）。
 * <p>
 * 覆盖启动期常见的三种误配，保证报错能直接指出：哪个 signer、明文还是加密 JWK、
 * 是内容缺 kty 还是解密口令缺失/错误——不再静默回退成误导性的 "Missing key type kty"。
 */
class JwkPrivateKeyHandleTest {

    private ECKey generateJwk(String kid) throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(kid).algorithm(JWSAlgorithm.ES256).generate();
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
    void fromContent_plainPrivateJwk_shouldLoad() throws Exception {
        ECKey jwk = generateJwk("kid-1");
        JwkPrivateKeyHandle handle = JwkPrivateKeyHandle.fromContent(jwk.toJSONString(), null);

        assertEquals("kid-1", handle.kid());
        assertEquals("EC", handle.keyType());
        assertEquals(JWSAlgorithm.ES256, handle.algorithm());
    }

    @Test
    void fromContent_encryptedJwkWithCorrectPassword_shouldDecrypt() throws Exception {
        ECKey jwk = generateJwk("kid-1");
        String content = encryptJwk(jwk.toJSONString(), "provisioner-secret");

        JwkPrivateKeyHandle handle = JwkPrivateKeyHandle.fromContent(content, "provisioner-secret");

        assertEquals("kid-1", handle.kid());
        assertDoesNotThrow(() -> handle.createSigner());
    }

    @Test
    void fromContent_encryptedJwkWithWrongPassword_shouldReportDecryptFailure() throws Exception {
        ECKey jwk = generateJwk("kid-1");
        String content = encryptJwk(jwk.toJSONString(), "provisioner-secret");

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> JwkPrivateKeyHandle.fromContent(content, "wrong-password"));

        assertTrue(ex.getMessage().contains("Failed to decrypt"),
                "解密失败必须显式报错，不得回退成 Missing kty: " + ex.getMessage());
        assertTrue(!ex.getMessage().contains("kty"));
    }

    @Test
    void fromContent_encryptedJwkWithoutPassword_shouldReportMissingPassword() throws Exception {
        ECKey jwk = generateJwk("kid-1");
        String content = encryptJwk(jwk.toJSONString(), "provisioner-secret");

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> JwkPrivateKeyHandle.fromContent(content, null));

        assertTrue(ex.getMessage().contains("decryption password is not configured"),
                "口令缺失必须显式报错: " + ex.getMessage());
    }

    @Test
    void fromContent_plainJsonMissingKty_shouldReportParseFailure() {
        // 最贴合本次 VMD 启动失败的形态：内容看似 JWK 但缺 kty
        String content = "{\"kid\":\"tbox-device-ecdh-v1\",\"crv\":\"P-256\",\"use\":\"sig\"}";

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> JwkPrivateKeyHandle.fromContent(content, null));

        assertTrue(ex.getMessage().contains("Failed to parse provisioner JWK"),
                "缺 kty 必须落到解析失败分支: " + ex.getMessage());
        assertTrue(ex.getCause() != null && ex.getCause().getMessage().contains("kty"));
    }

    @Test
    void fromContent_encryptedKeyEmbeddedProvisioner_shouldDecrypt() throws Exception {
        // step-ca ca.json 形态：公开 JWK 字段 + 同级 encryptedKey（JWE compact）
        ECKey jwk = generateJwk("kid-1");
        JWEObject jwe = new JWEObject(
                new JWEHeader(JWEAlgorithm.PBES2_HS256_A128KW, EncryptionMethod.A128CBC_HS256),
                new Payload(jwk.toJSONString()));
        jwe.encrypt(new PasswordBasedEncrypter("provisioner-secret", 16, 1000));

        String content = "{\"kty\":\"EC\",\"kid\":\"kid-1\",\"crv\":\"P-256\",\"x\":\""
                + jwk.getX() + "\",\"y\":\"" + jwk.getY() + "\",\"encryptedKey\":\""
                + jwe.serialize() + "\"}";

        JwkPrivateKeyHandle handle = JwkPrivateKeyHandle.fromContent(content, "provisioner-secret");
        assertEquals("kid-1", handle.kid());
        assertDoesNotThrow(() -> handle.createSigner());
    }
}
