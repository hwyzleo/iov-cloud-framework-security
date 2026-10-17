package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;

/**
 * 证书材料解析配置校验（FW-SEC-DSN-CR-012 §8；决策：强门禁前移到启动/readiness）。
 * <p>
 * 两条硬门禁：
 * <ul>
 *   <li>{@code business-key-wrap.require-trusted-chain=true}（默认）时，
 *       {@code trust-anchors-pem} 必须显式配置，<b>不</b>接受从 TLS 传输信任或吊销查询 issuer 隐式回退；</li>
 *   <li>{@code business-key-wrap.require-good-status=true}（默认）时，
 *       必须启用 {@code crypto.pki.revocation.enabled=true}，否则启动失败 / readiness NOT_READY，
 *       不得等首次 Wrap 才报错，也不得静默跳过（dev/test 可显式关闭该策略）。</li>
 * </ul>
 */
public final class CertificateResolutionValidator {

    private CertificateResolutionValidator() {
    }

    /**
     * 返回未就绪原因；配置合法时返回 {@code null}。
     */
    public static String inspect(CryptoProperties properties, boolean revocationEnabled) {
        if (properties == null || properties.getPki() == null) {
            return "crypto.pki configuration is missing";
        }
        CryptoProperties.Pki.CertificateResolution config = properties.getPki().getCertificateResolution();
        if (config == null || !config.isEnabled()) {
            return null;
        }
        CryptoProperties.Pki.BusinessKeyWrap businessKeyWrap = config.getBusinessKeyWrap();
        boolean requireTrustedChain = businessKeyWrap == null || businessKeyWrap.isRequireTrustedChain();
        boolean requireGoodStatus = businessKeyWrap == null || businessKeyWrap.isRequireGoodStatus();

        if (requireTrustedChain && isBlank(config.getTrustAnchorsPem())) {
            return "crypto.pki.certificate-resolution.trust-anchors-pem is required when resolving "
                    + "certificate material with trusted-chain policy; no implicit fallback to TLS or "
                    + "revocation trust anchors";
        }
        if (requireGoodStatus && !revocationEnabled) {
            return "crypto.pki.certificate-resolution.business-key-wrap.require-good-status=true requires "
                    + "crypto.pki.revocation.enabled=true (or explicitly disable require-good-status in dev/test)";
        }
        return null;
    }

    /**
     * 启动校验：配置非法时 fail-closed 抛出。
     */
    public static void validate(CryptoProperties properties, boolean revocationEnabled) {
        String reason = inspect(properties, revocationEnabled);
        if (reason != null) {
            throw new IllegalStateException(reason);
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
