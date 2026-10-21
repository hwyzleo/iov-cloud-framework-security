package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.enrollment.DefaultJwkSignerRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.JwkPrivateKeyHandle;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.JwkSignerDescriptor;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.JwkSignerRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaProfileRouteResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * step-ca 命名 JWK signer registry 工厂（FW-SEC-DSN-CR-018 §6/§8）。
 * <p>
 * 启动阶段构建不可变 registry，执行 §8 配置校验并 fail-closed：
 * <ol>
 *   <li>signerRef 格式、唯一性与保留名（{@code __legacy__} 保留）；</li>
 *   <li>legacy 单 JWK 映射为保留 signer {@code __legacy__}（RD-018-4）；</li>
 *   <li>私钥来源不冲突（file/content 二选一）、文件可读、密码来源不冲突；</li>
 *   <li>JWK 为可签名私钥、算法允许；配置 kid 与 JWK 自身 kid 一致；</li>
 *   <li>未使用 signer 告警但不得被自动选中（§8.6）。</li>
 * </ol>
 * 不发起任何网络调用，便于启动期 fail-fast 与单测。
 */
public final class StepCaJwkSignerRegistryFactory {

    private static final Logger log = LoggerFactory.getLogger(StepCaJwkSignerRegistryFactory.class);

    private StepCaJwkSignerRegistryFactory() {
    }

    /**
     * 构建不可变 signer registry（FW-SEC-DSN-CR-018 §6/§8）。
     */
    public static JwkSignerRegistry create(CryptoProperties.Pki.StepCa stepCa) {
        if (!"jwk".equalsIgnoreCase(stepCa.getTokenProvider())) {
            throw new IllegalStateException("Unsupported step-ca token-provider: "
                    + stepCa.getTokenProvider() + " (only 'jwk' is currently supported)");
        }
        CryptoProperties.Pki.Jwk jwk = stepCa.getJwk();
        Map<String, JwkSignerDescriptor> descriptors = new LinkedHashMap<>();

        // RD-018-4：legacy 单 JWK（仅当配置了任一私钥来源才登记；未配置且 Profile 回退到 legacy 时启动失败）
        if (hasAnyKeySource(jwk)) {
            descriptors.put(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, buildSignerDescriptor(
                    StepCaProfileRouteResolver.LEGACY_SIGNER_REF, null, null,
                    jwk.getPrivateKeyFile(), jwk.getPasswordFile(),
                    jwk.getPrivateKeyContent(), jwk.getPassword(), false));
        }

        // 命名 signer：map key 为稳定非敏感 signerRef（RD-018-2），不允许保留名
        for (Map.Entry<String, CryptoProperties.Pki.JwkSignerProperties> entry : jwk.getSigners().entrySet()) {
            String signerRef = entry.getKey();
            validateSignerRef(signerRef);
            CryptoProperties.Pki.JwkSignerProperties signer = entry.getValue();
            descriptors.put(signerRef, buildSignerDescriptor(
                    signerRef, signer.getProvisioner(), signer.getKid(),
                    signer.getPrivateKeyFile(), signer.getPasswordFile(),
                    signer.getPrivateKeyContent(), signer.getPassword(), true));
        }

        // §8.6：未使用的 signer 可告警，但不得被自动选中
        warnUnusedSigners(stepCa, descriptors.keySet());
        return new DefaultJwkSignerRegistry(descriptors);
    }

    /**
     * 构建单个 signer 描述并执行启动校验（FW-SEC-DSN-CR-018 §8）。
     */
    private static JwkSignerDescriptor buildSignerDescriptor(String signerRef,
                                                             String provisioner,
                                                             String kid,
                                                             String privateKeyFile,
                                                             String passwordFile,
                                                             String privateKeyContent,
                                                             String password,
                                                             boolean warnInlineContent) {
        boolean hasFile = notBlank(privateKeyFile);
        boolean hasContent = notBlank(privateKeyContent);
        // §8.4：私钥来源不冲突
        if (hasFile && hasContent) {
            throw new IllegalStateException(
                    "step-ca signer '" + signerRef + "' private key source conflict: configure either "
                            + "private-key-file or private-key-content, not both (FW-SEC-DSN-CR-018 §8)");
        }
        boolean hasPassword = notBlank(password);
        boolean hasPasswordFile = notBlank(passwordFile);
        // §8.4：密码来源不冲突
        if (hasPassword && hasPasswordFile) {
            throw new IllegalStateException(
                    "step-ca signer '" + signerRef + "' password source conflict: configure either "
                            + "password or password-file, not both (FW-SEC-DSN-CR-018 §8)");
        }

        JwkPrivateKeyHandle handle;
        if (hasContent) {
            if (warnInlineContent) {
                log.warn("step-ca signer '{}' 使用内联 JWK 内容（配置中心下发）；生产优先 file/Secret Provider "
                        + "（FW-SEC-DSN-CR-018 §5.2）", signerRef);
            }
            handle = JwkPrivateKeyHandle.fromContent(privateKeyContent.trim(), password);
        } else if (hasFile) {
            Path keyPath = Path.of(privateKeyFile);
            if (!Files.isReadable(keyPath)) {
                throw new IllegalStateException(
                        "step-ca signer '" + signerRef + "' private key file is not readable: " + keyPath
                                + " (must be mounted read-only Secret)");
            }
            Path passwordPath = hasPasswordFile ? Path.of(passwordFile) : null;
            if (passwordPath != null && !Files.isReadable(passwordPath)) {
                throw new IllegalStateException(
                        "step-ca signer '" + signerRef + "' password file is not readable: " + passwordPath);
            }
            handle = JwkPrivateKeyHandle.fromFile(keyPath, passwordPath);
        } else {
            throw new IllegalStateException(
                    "step-ca signer '" + signerRef + "' requires a private key source: configure either "
                            + "private-key-file or private-key-content (FW-SEC-DSN-CR-018 §8)");
        }

        // §8.5：配置 kid 与 JWK 自身 kid 一致性（仅对显式声明 kid 的命名 signer 强制；legacy 保持兼容）
        if (kid != null && handle.kid() != null && !kid.equals(handle.kid())) {
            throw new IllegalStateException(
                    "step-ca signer '" + signerRef + "' configured kid='" + kid + "' does not match the "
                            + "JWK's own kid='" + handle.kid() + "' (FW-SEC-DSN-CR-018 §8.5)");
        }
        log.info("step-ca signer '{}' 装配完成: provisioner={}, kid={}, kty={}, alg={}",
                signerRef, provisioner, kid, handle.keyType(), handle.algorithm());
        return new JwkSignerDescriptor(signerRef, provisioner, kid, handle);
    }

    /**
     * §8.1：signerRef 格式、唯一性与保留名。
     */
    private static void validateSignerRef(String signerRef) {
        if (signerRef == null || signerRef.isBlank()) {
            throw new IllegalStateException("step-ca signer map key (signerRef) must not be blank "
                    + "(FW-SEC-DSN-CR-018 §8.1)");
        }
        if (signerRef.equals(StepCaProfileRouteResolver.LEGACY_SIGNER_REF)) {
            throw new IllegalStateException("signerRef '" + signerRef + "' is a reserved internal reference "
                    + "(legacy single JWK route); use a non-reserved signerRef (FW-SEC-DSN-CR-018 §8.1)");
        }
        if (signerRef.trim().contains(" ") || signerRef.startsWith("__")) {
            throw new IllegalStateException("signerRef '" + signerRef + "' is invalid: must be a stable, "
                    + "non-sensitive token without spaces and without the reserved '__' prefix "
                    + "(FW-SEC-DSN-CR-018 §8.1)");
        }
    }

    /**
     * §8.6：未使用的 signer 告警，但不得被自动选中。
     */
    private static void warnUnusedSigners(CryptoProperties.Pki.StepCa stepCa, Set<String> registeredRefs) {
        Set<String> referenced = new LinkedHashSet<>();
        for (String profileName : stepCa.getProfiles().keySet()) {
            String ref = stepCa.getProfiles().get(profileName).getJwkSignerRef();
            if (ref != null && !ref.isBlank()) {
                referenced.add(ref.trim());
            }
        }
        for (String ref : registeredRefs) {
            if (!referenced.contains(ref)) {
                log.warn("step-ca signer '{}' is not referenced by any enabled profile; it will not be "
                        + "auto-selected (FW-SEC-DSN-CR-018 §8.6)", ref);
            }
        }
    }

    private static boolean hasAnyKeySource(CryptoProperties.Pki.Jwk jwk) {
        return notBlank(jwk.getPrivateKeyFile()) || notBlank(jwk.getPrivateKeyContent());
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }
}
