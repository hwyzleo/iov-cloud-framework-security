package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;

import java.util.Objects;

/**
 * 证书解析器门面（FW-SEC-DSN-CR-012 §5）。
 * <p>
 * framework 对内稳定门面。默认实现 {@link DefaultCertResolver} 为受治理的解析编排链：
 * inline DER → inline SPKI（policy 允许）→ requestId/result store → Provider serial query
 * → 领域目录 locator，并按策略经 {@link CertificateEvidenceValidator} 统一校验。
 * <p>
 * <strong>职责边界</strong>：framework 不拥有主体/serial 目录权威；VMD/TSP/KTS 等领域方
 * 仅实现薄的 {@link CertificateReferenceDirectory}，不复制 X.509 解析、链校验、用途校验、
 * 状态查询或 Provider 差异处理。自定义 {@link CertResolver} 仍可通过
 * {@code @ConditionalOnMissingBean} 覆盖默认 Bean。
 * <p>
 * <strong>兼容性</strong>：下述四个按主体解析的既有方法保持为抽象方法，存量自定义实现无需
 * 改动即可继续编译；新的证据化 {@link #resolve(DeviceCertificateRef, CertificateResolvePolicy)}
 * 提供默认实现，可回退到 inline 证据、主体/序列号解析。
 */
public interface CertResolver {

    /**
     * 按 VIN 解析收方证书 DER（既有方法，保持抽象以向后兼容）。
     *
     * @param vin VIN
     * @return 证书 DER 编码
     * @deprecated 新代码请使用 {@link #resolve(DeviceCertificateRef, CertificateResolvePolicy)}
     */
    @Deprecated
    byte[] resolveByVin(String vin);

    /**
     * 按设备 SN 解析收方证书 DER（既有方法，保持抽象以向后兼容）。
     *
     * @param deviceSn 设备 SN
     * @return 证书 DER 编码
     * @deprecated 新代码请使用 {@link #resolve(DeviceCertificateRef, CertificateResolvePolicy)}
     */
    @Deprecated
    byte[] resolveByDeviceSn(String deviceSn);

    /**
     * 按 UID 解析收方证书 DER（既有方法，保持抽象以向后兼容）。
     *
     * @param uid 用户唯一标识
     * @return 证书 DER 编码
     * @deprecated 新代码请使用 {@link #resolve(DeviceCertificateRef, CertificateResolvePolicy)}
     */
    @Deprecated
    byte[] resolveByUid(String uid);

    /**
     * 按证书序列号解析收方证书 DER（既有方法，保持抽象以向后兼容）。
     *
     * @param certSerial 证书序列号
     * @return 证书 DER 编码
     * @deprecated 新代码请使用 {@link #resolve(DeviceCertificateRef, CertificateResolvePolicy)}
     */
    @Deprecated
    byte[] resolveBySerial(String certSerial);

    /**
     * 按证据优先级统一解析证书（新方法，默认实现可回退到 inline 证据与既有主体/序列号解析）。
     * <p>
     * 返回的证据须经 {@link CertificateEvidenceValidator#validate} 按场景策略校验后方可使用；
     * 任一路径缺少材料、来源缺失或结果冲突时 fail-closed。
     *
     * @param ref    证书引用 / 证据输入
     * @param policy 解析 / 校验策略（决定可用来源与校验深度）
     * @return 规范化证书证据
     */
    default CertificateEvidence resolve(DeviceCertificateRef ref, CertificateResolvePolicy policy) {
        Objects.requireNonNull(ref, "ref must not be null");
        Objects.requireNonNull(policy, "policy must not be null");

        if (ref.hasInlineDer()) {
            return CertificateEvidenceValidator.fromCertificateDer(
                    ref.certificateDer(), EvidenceSource.INLINE_DER);
        }
        if (ref.hasInlineSpki() && policy.allowBareSpki()) {
            return CertificateEvidenceValidator.fromSpki(
                    ref.spki(), ref.sha256Fingerprint(), EvidenceSource.INLINE_SPKI);
        }
        if (ref.subject() != null) {
            byte[] der = switch (ref.subject().type()) {
                case VEHICLE -> resolveByVin(ref.subject().value());
                case DEVICE -> resolveByDeviceSn(ref.subject().value());
                case USER -> resolveByUid(ref.subject().value());
            };
            return fromResolvedDer(der, EvidenceSource.DOMAIN_DIRECTORY, ref.subject().value());
        }
        if (ref.certSerial() != null && !ref.certSerial().isBlank()) {
            byte[] der = resolveBySerial(ref.certSerial());
            return fromResolvedDer(der, EvidenceSource.PROVIDER_QUERY, ref.certSerial());
        }
        throw new CertificateMaterialUnavailableException(
                "No certificate evidence source available for ref (no inline DER/SPKI, subject or certSerial)");
    }

    private static CertificateEvidence fromResolvedDer(byte[] der, EvidenceSource source, String target) {
        if (der == null || der.length == 0) {
            throw new CertificateMaterialUnavailableException(
                    "Certificate not resolvable for: " + target);
        }
        return CertificateEvidenceValidator.fromCertificateDer(der, source);
    }
}
