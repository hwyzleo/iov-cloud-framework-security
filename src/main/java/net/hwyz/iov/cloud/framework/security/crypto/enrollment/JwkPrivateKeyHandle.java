package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * 不可变 JWK 私钥句柄（FW-SEC-DSN-CR-018 §6）。
 * <p>
 * 只承载已加载/解密的私钥 JWK，并负责：
 * <ul>
 *   <li>从只读 Secret 文件（明文 JWK 或 step-ca 口令加密 JWK）或内联内容装载；</li>
 *   <li>校验必须为可签名私钥（EC/RSA 且含私钥参数，FW-SEC-DSN-CR-018 §8.5）；</li>
 *   <li>导出签名算法与 {@link JWSSigner}、公开 JWK（供启动期 route 校验）；</li>
 *   <li>{@link #toString()} 只回显 kid/kty/alg，<strong>严禁泄漏私钥参数</strong>。</li>
 * </ul>
 * 私钥句柄不得出现在日志、异常消息、Health detail 或配置回显中
 * （FW-SEC-DSN-CR-018 §6）。
 */
public final class JwkPrivateKeyHandle {

    private final JWK jwk;
    private final JWSAlgorithm algorithm;

    private JwkPrivateKeyHandle(JWK jwk) {
        Objects.requireNonNull(jwk, "jwk must not be null");
        if (!jwk.isPrivate()) {
            throw new IllegalStateException(
                    "Provisioner JWK must be a private signing key, but the loaded JWK contains no "
                            + "private key parameters (FW-SEC-DSN-CR-018 §8.5): kty=" + jwk.getKeyType());
        }
        if (!(jwk instanceof ECKey) && !(jwk instanceof RSAKey)) {
            throw new IllegalStateException(
                    "Provisioner JWK type is not supported for OTT signing: kty=" + jwk.getKeyType()
                            + " (only EC/RSA private JWK are supported, FW-SEC-DSN-CR-018 §8.5)");
        }
        this.jwk = jwk;
        this.algorithm = resolveAlgorithm(jwk);
    }

    /**
     * 从只读 Secret 文件装载（明文 JWK 或 step-ca 口令加密 JWK）。
     *
     * @param privateKeyFile 私钥文件路径（必填，可读）
     * @param passwordFile   解密口令文件路径（仅加密 JWK 需要；可为 null）
     */
    public static JwkPrivateKeyHandle fromFile(Path privateKeyFile, Path passwordFile) {
        Objects.requireNonNull(privateKeyFile, "privateKeyFile must not be null");
        String json = readFile(privateKeyFile);
        String password = readPassword(passwordFile);
        return new JwkPrivateKeyHandle(loadJwk(json, password));
    }

    /**
     * 从内联 JWK 内容装载（配置中心/Nacos 下发）。
     * <p>
     * {@code jwkContent} 建议为 step-ca 口令加密 JWK（含 {@code encryptedKey}，密文安全可入 Nacos）；
     * {@code password} 为解密口令，建议以环境变量占位符注入，勿在 Nacos 明文保存。
     */
    public static JwkPrivateKeyHandle fromContent(String jwkContent, String password) {
        if (jwkContent == null || jwkContent.isBlank()) {
            throw new IllegalStateException("step-ca JWK content must not be blank");
        }
        return new JwkPrivateKeyHandle(loadJwk(jwkContent.trim(),
                password == null || password.isBlank() ? null : password.trim()));
    }

    /**
     * JWK 的 kid（可为 null）。
     */
    public String kid() {
        return jwk.getKeyID();
    }

    /**
     * JWK 类型（如 EC/RSA）。
     */
    public String keyType() {
        return jwk.getKeyType() == null ? null : jwk.getKeyType().getValue();
    }

    /**
     * OTT 签名算法（由 JWK 声明或按曲线推导）。
     */
    public JWSAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * 生成 JOSE 签名器。
     */
    public JWSSigner createSigner() throws JOSEException {
        if (jwk instanceof ECKey ecKey) {
            return new ECDSASigner(ecKey.toECPrivateKey());
        }
        if (jwk instanceof RSAKey rsaKey) {
            return new RSASSASigner(rsaKey.toRSAPrivateKey());
        }
        throw new IllegalStateException("Unsupported JWK type for OTT signing: " + jwk.getKeyType());
    }

    /**
     * 提取公开 JWK（移除私钥参数），仅供启动期 route/参数校验，不得回显私钥。
     */
    public JWK publicJwk() {
        if (jwk instanceof ECKey ecKey) {
            return ecKey.toPublicJWK();
        }
        if (jwk instanceof RSAKey rsaKey) {
            return rsaKey.toPublicJWK();
        }
        return jwk;
    }

    private static String readFile(Path privateKeyFile) {
        try {
            return Files.readString(privateKeyFile, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read provisioner JWK file: " + privateKeyFile, e);
        }
    }

    private static String readPassword(Path passwordFile) {
        if (passwordFile == null || !Files.isReadable(passwordFile)) {
            return null;
        }
        try {
            return Files.readString(passwordFile, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read provisioner JWK password file: " + passwordFile, e);
        }
    }

    private static JWK loadJwk(String json, String password) {
        if (password != null) {
            try {
                JWK decrypted = decryptEncryptedJwk(json, password);
                return decrypted;
            } catch (Exception e) {
                // 尝试按明文 JWK 解析
            }
        }
        try {
            return JWK.parse(json);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse provisioner JWK", e);
        }
    }

    /**
     * 解密 step-ca 发布的口令加密 JWK，支持两种形态：
     * <ol>
     *   <li>step-ca ca.json 中的 provisioner JWK：公开 JWK 字段 + {@code encryptedKey}（JWE compact，PBES2）；</li>
     *   <li>独立 JWE JSON 序列化（protected/encrypted_key/iv/ciphertext/tag）。</li>
     * </ol>
     */
    private static JWK decryptEncryptedJwk(String json, String password) throws Exception {
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

    private static JWSAlgorithm resolveAlgorithm(JWK jwk) {
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

    @Override
    public String toString() {
        return "JwkPrivateKeyHandle{kid=" + kid() + ", kty=" + keyType() + ", alg=" + algorithm
                + "}";
    }
}
