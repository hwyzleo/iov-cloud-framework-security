package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.FailClosedCertResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Clock;
import java.util.Objects;

/**
 * Keyprov 证书 Profile / 完整 ECDH-ES v1 聚合就绪状态（FW-SEC-DSN-CR-017 §9）。
 * <p>
 * 聚合门禁：
 * <pre>
 * KEYPROV_CERTIFICATE_READY =
 *   profileValidatorBeanReady            // TboxDeviceCertificateValidator Bean 已装配
 *   AND trustAndStatusReady              // 吊销组件装配 &&（要求受信链时信任锚已配置）&& 解析非 fail-closed
 *   AND controlledClockReady             // 框架受控 Clock 可用
 *   AND p256PolicyReady                  // 正向量自检通过（P-256）
 *   AND digitalSignaturePolicyReady      // 正向量自检通过（digitalSignature）
 *   AND keyAgreementPolicyReady          // 正向量自检通过（keyAgreement）
 *   AND clientAuthPolicyReady            // 正向量自检通过（clientAuth）
 *   AND leafDerDigestReady               // leaf DER digest 可计算（正向量自检）

 * KEYPROV_ECDH_ES_V1_READY =
 *   KEYPROV_CERTIFICATE_READY
 *   AND provisioningEnabled
 *   AND importProofReady                 // import-proof 装配 && capability 自检
 *   AND envelopeCapabilitiesReady        // STRUCTURED_ENVELOPE_VIEW_V1 + CORE_ENVELOPE_DIGEST_VERIFY_V1
 * </pre>
 * <p>
 * Profile / provisioning / import-proof 可独立装配；关闭时不声明对应 capability，完整
 * {@code KEYPROV_ECDH_ES_V1_READY} 必须聚合三者及 envelope/verifier 能力（FW-SEC-DSN-CR-017 决策 3），
 * <strong>禁止</strong>单边 READY 被 VMD 解释为完整能力。
 * <p>
 * 吊销组件未装配（{@code crypto.pki.revocation.enabled != true}）时 Profile / 完整 Keyprov
 * readiness 必须 DOWN（用户决策）：生产验证不得静默跳过吊销门禁。
 */
public class KeyprovReadiness {

    private static final Logger log = LoggerFactory.getLogger(KeyprovReadiness.class);

    private final CryptoProperties properties;
    private final ObjectProvider<TboxDeviceCertificateValidator> validatorProvider;
    private final ObjectProvider<Clock> clockProvider;
    private final CertResolver certResolver;
    private final boolean revocationEnabled;

    public KeyprovReadiness(CryptoProperties properties,
                            ObjectProvider<TboxDeviceCertificateValidator> validatorProvider,
                            ObjectProvider<Clock> clockProvider,
                            CertResolver certResolver,
                            boolean revocationEnabled) {
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.validatorProvider = validatorProvider;
        this.clockProvider = clockProvider;
        this.certResolver = certResolver;
        this.revocationEnabled = revocationEnabled;
    }

    /**
     * 是否装配统一 TBOX 设备证书 Profile 能力。
     */
    public boolean certificateProfileEnabled() {
        return properties.getKeyprov().getCertificateProfile().isEnabled();
    }

    /**
     * {@code KEYPROV_CERTIFICATE_READY} 未就绪原因；READY 返回 {@code null}。
     */
    public String keyprovCertificateReadyReason() {
        CryptoProperties.KeyprovProfile.CertificateProfile config = properties.getKeyprov().getCertificateProfile();
        if (!config.isEnabled()) {
            return "TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1 disabled: "
                    + "set crypto.keyprov.certificate-profile.enabled=true";
        }
        if (validatorProvider == null || validatorProvider.getIfAvailable() == null) {
            return "TboxDeviceCertificateValidator bean is not assembled "
                    + "(crypto.keyprov.certificate-profile.enabled=true required)";
        }
        if (!KeyprovCertificateProfileCapability.selfCheckReady()) {
            return "TBOX device certificate profile capability self-check failed "
                    + "(public API / P-256 / dual-KU / clientAuth / CA=false / critical-extension "
                    + "/ identity / leaf DER digest vectors)";
        }
        // controlledClockReady：框架受控 Clock 必须可用
        if (clockProvider == null || clockProvider.getIfAvailable() == null) {
            return "controlled Clock is not available";
        }
        if (!revocationEnabled) {
            return "crypto.pki.revocation.enabled=true is required for TBOX device certificate profile "
                    + "readiness (吊销组件未装配时 Profile readiness 必须 DOWN, FW-SEC-DSN-CR-017)";
        }
        if (config.isRequireTrustedChain() && isBlank(
                properties.getPki().getCertificateResolution().getTrustAnchorsPem())) {
            return "crypto.pki.certificate-resolution.trust-anchors-pem is required when "
                    + "crypto.keyprov.certificate-profile.require-trusted-chain=true";
        }
        if (certResolver == null || certResolver instanceof FailClosedCertResolver) {
            return "CertResolver is fail-closed: enable crypto.pki.certificate-resolution.enabled "
                    + "or provide a custom CertResolver";
        }
        return null;
    }

    /**
     * {@code KEYPROV_CERTIFICATE_READY}。
     */
    public boolean keyprovCertificateReady() {
        return keyprovCertificateReadyReason() == null;
    }

    /**
     * {@code KEYPROV_ECDH_ES_V1_READY} 未就绪原因；READY 返回 {@code null}。
     */
    public String keyprovEcdhEsV1ReadyReason() {
        String certificateReason = keyprovCertificateReadyReason();
        if (certificateReason != null) {
            return "KEYPROV_CERTIFICATE_READY 未就绪: " + certificateReason;
        }
        if (!properties.getProvisioning().isEnabled()) {
            return "crypto.provisioning.enabled=true is required for KEYPROV_ECDH_ES_V1_READY";
        }
        if (!properties.getImportProof().isEnabled()) {
            return "crypto.import-proof.enabled=true is required for KEYPROV_ECDH_ES_V1_READY";
        }
        if (!ImportProofCapability.selfCheckReady()) {
            return "IMPORT_PROOF_VERIFY_ECDSA_P256_V1 capability is not ready";
        }
        if (!DerivedEnvelopeCapability.supports(DerivedEnvelopeCapability.STRUCTURED_ENVELOPE_VIEW_V1)
                || !DerivedEnvelopeCapability.coreDigestVerifyReady()) {
            return "envelope capabilities not ready "
                    + "(STRUCTURED_ENVELOPE_VIEW_V1 / CORE_ENVELOPE_DIGEST_VERIFY_V1)";
        }
        return null;
    }

    /**
     * {@code KEYPROV_ECDH_ES_V1_READY}。
     */
    public boolean keyprovEcdhEsV1Ready() {
        return keyprovEcdhEsV1ReadyReason() == null;
    }

    /**
     * 启动门禁：完整 Keyprov readiness 未就绪时抛异常使应用启动 fail-closed
     * （受 {@code crypto.keyprov.certificate-profile.require-ready-at-startup} 控制）。
     */
    public void verifyAtStartup() {
        String reason = keyprovCertificateReadyReason();
        if (reason != null) {
            throw new IllegalStateException(
                    "TBOX 设备证书 Profile capability 未 READY，启动 fail-closed"
                            + "（FW-SEC-DSN-CR-017 §9）: " + reason);
        }
        log.info("TBOX 设备证书 Profile capability READY: capability={}",
                KeyprovCertificateProfileCapability.TBOX_DEVICE_CERT_PROFILE_ECDH_ES_P256_V1);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
