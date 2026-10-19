package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.FailClosedCertResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 导入证明验签能力就绪状态（FW-SEC-DSN-CR-016 §8）。
 * <p>
 * READY 需同时满足：
 * <ul>
 *   <li>{@link ImportProofCapability} 静态自检通过（公开 API、canonical {@code proofInputV1} 固定向量、
 *       P1363/low-S codec、ECDSA P-256/SHA-256 Provider）；</li>
 *   <li>{@link CertResolver} 非 fail-closed（未启用解析能力且无自定义解析器时为 {@code DOWN}）；</li>
 *   <li>证书策略与解析配置自洽：要求受信链时须显式配置信任锚，要求 GOOD 状态时须启用吊销查询。</li>
 * </ul>
 * DOWN 时允许 canonical 构造与诊断，但<strong>不得</strong>向 VMD 声明 proof verification READY，
 * 也不得回退到仅校验 ACK 字段、KCV 或 {@code ImportProofCanonical.matches}。
 */
public class ImportProofReadiness {

    private static final Logger log = LoggerFactory.getLogger(ImportProofReadiness.class);

    private final CryptoProperties properties;
    private final CertResolver certResolver;
    private final boolean revocationEnabled;

    public ImportProofReadiness(CryptoProperties properties, CertResolver certResolver,
                                boolean revocationEnabled) {
        this.properties = properties;
        this.certResolver = certResolver;
        this.revocationEnabled = revocationEnabled;
    }

    /**
     * 就绪自检；返回未就绪原因，READY 时返回 {@code null}。
     */
    public String notReadyReason() {
        if (!ImportProofCapability.selfCheckReady()) {
            return "import-proof capability self-check failed (public API / canonical vector / "
                    + "P1363 codec / ECDSA P-256 provider)";
        }
        if (certResolver == null || certResolver instanceof FailClosedCertResolver) {
            return "CertResolver is fail-closed: enable crypto.pki.certificate-resolution.enabled "
                    + "or provide a custom CertResolver";
        }
        CryptoProperties.ImportProof.Certificate certificate = properties.getImportProof().getCertificate();
        CryptoProperties.Pki.CertificateResolution resolution =
                properties.getPki().getCertificateResolution();
        if (certificate.isRequireTrustedChain() && isBlank(resolution.getTrustAnchorsPem())) {
            return "crypto.pki.certificate-resolution.trust-anchors-pem is required when "
                    + "crypto.import-proof.certificate.require-trusted-chain=true "
                    + "(no implicit fallback to TLS or revocation trust anchors)";
        }
        if (certificate.isRequireGoodStatus() && !revocationEnabled) {
            return "crypto.import-proof.certificate.require-good-status=true requires "
                    + "crypto.pki.revocation.enabled=true (or explicitly disable require-good-status in dev/test)";
        }
        return null;
    }

    /**
     * 能力是否 READY。
     */
    public boolean isReady() {
        return notReadyReason() == null;
    }

    /**
     * 启动门禁：未 READY 抛异常使应用启动 fail-closed（受
     * {@code crypto.import-proof.require-ready-at-startup} 控制）。
     */
    public void verifyAtStartup() {
        String reason = notReadyReason();
        if (reason != null) {
            throw new IllegalStateException(
                    "导入证明验签 capability 未 READY，启动 fail-closed（FW-SEC-DSN-CR-016 §8）: " + reason);
        }
        log.info("导入证明验签 capability READY: capability={}",
                ImportProofCapability.IMPORT_PROOF_VERIFY_ECDSA_P256_V1);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
