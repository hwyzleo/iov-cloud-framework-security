package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import java.io.Serializable;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * 证书解析 / 校验策略（FW-SEC-DSN-CR-012 §5/§6）。
 * <p>
 * 区分调用场景（{@link Scenario}），按场景治理校验深度：是否必须 leaf DER、
 * 是否允许裸 SPKI、是否要求受信链、是否要求吊销状态 GOOD，以及算法 / EKU 白名单。
 * 具体取值可由 {@code crypto.pki.certificate-resolution.business-key-wrap.*} 覆盖（dev/test 可显式放宽）。
 *
 * @param scenario                 调用场景
 * @param requireLeafDer           是否必须取得叶子证书 DER
 * @param allowBareSpki            是否允许仅用裸 SPKI（无证书）
 * @param requireTrustedChain      是否要求证书链/issuer 可验证到配置信任锚
 * @param requireGoodStatus        是否要求吊销状态为 GOOD（UNKNOWN 视为不可用）
 * @param allowedKeyAlgorithms     允许的公钥算法（空集表示不限制）
 * @param requiredExtendedKeyUsage 必须包含的 EKU（空集表示不强制；证书无 EKU 时视为不满足）
 */
public record CertificateResolvePolicy(
        Scenario scenario,
        boolean requireLeafDer,
        boolean allowBareSpki,
        boolean requireTrustedChain,
        boolean requireGoodStatus,
        Set<String> allowedKeyAlgorithms,
        Set<String> requiredExtendedKeyUsage
) implements Serializable {

    public enum Scenario {
        /**
         * 用证书/公钥加密门面（CertEncryptionTemplate）
         */
        CERT_ENCRYPTION,
        /**
         * 业务密钥 DEVICE_CERT_PUBLIC_KEY 封装（BusinessKeyMaterialTemplate）
         */
        BUSINESS_KEY_WRAP,
        /**
         * 证书状态查询上下文解析（PkiClient.checkCertificateStatus）
         */
        REVOCATION_CHECK
    }

    public CertificateResolvePolicy {
        Objects.requireNonNull(scenario, "scenario must not be null");
        allowedKeyAlgorithms = allowedKeyAlgorithms == null
                ? Set.of() : Set.copyOf(new LinkedHashSet<>(allowedKeyAlgorithms));
        requiredExtendedKeyUsage = requiredExtendedKeyUsage == null
                ? Set.of() : Set.copyOf(new LinkedHashSet<>(requiredExtendedKeyUsage));
    }

    /**
     * 证书加密场景：允许裸 SPKI，不强制信任链与吊销状态（加密收方可直接给定材料）。
     */
    public static CertificateResolvePolicy certEncryption() {
        return new CertificateResolvePolicy(Scenario.CERT_ENCRYPTION, false, true, false, false,
                Set.of("RSA", "EC", "Ed25519"), Set.of());
    }

    /**
     * 业务密钥封装场景：默认要求叶子 DER + 受信链 + GOOD 状态（由配置覆盖）。
     */
    public static CertificateResolvePolicy businessKeyWrap(boolean requireCertificate,
                                                           boolean requireTrustedChain,
                                                           boolean requireGoodStatus) {
        return new CertificateResolvePolicy(Scenario.BUSINESS_KEY_WRAP, requireCertificate, false,
                requireTrustedChain, requireGoodStatus, Set.of("RSA", "EC"), Set.of());
    }

    /**
     * 证书状态查询场景：要求叶子 DER 与受信链，状态由状态查询本身负责。
     */
    public static CertificateResolvePolicy revocationCheck() {
        return new CertificateResolvePolicy(Scenario.REVOCATION_CHECK, true, false, true, false,
                Set.of("RSA", "EC", "Ed25519"), Set.of());
    }
}
