package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceCertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.ValidatedTboxDeviceCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;

/**
 * 统一 TBOX 设备证书 Profile 验证器（FW-SEC-DSN-CR-017 §4）。
 * <p>
 * 作为 CR-014（ECDH-ES 封装收方）与 CR-016（Import Attestation 验签证书）的<strong>共同
 * 证书验证入口</strong>：两条路径必须解析并验证同一 {@code DeviceCertificateRef} 与同一
 * {@link DeviceCertificateProfile}，共享同一 leaf DER 摘要与 freshness 语义（RD-017-2/RD-017-3）。
 * <p>
 * 固定校验流水线（FW-SEC-DSN-CR-017 §5）：
 * <pre>
 * resolve DeviceCertificateRef
 * → parse leaf（复用 CertificateEvidenceValidator 的链/有效期/吊销）
 * → leaf CA=false
 * → EC P-256
 * → KU 含 digitalSignature AND keyAgreement
 * → EKU 含 clientAuth 且无冲突（allowlist 仅 clientAuth）
 * → identity / Profile / critical extensions
 * → leaf DER digest
 * → 返回不可变已校验证据
 * </pre>
 * Profile 实现<strong>不得</strong>因当前调用只需要一个 KU 而跳过另一个 KU（RD-017-4）。
 */
public interface TboxDeviceCertificateValidator {

    /**
     * 校验指定 {@code ref} 是否满足给定 {@code profile}，返回不可变验证结果。
     *
     * @param ref     证书引用（解析输入；含证据/期望指纹）
     * @param profile 目标 Profile（首期仅 TBOX_DEVICE_ECDH_ES_P256_V1）
     * @return 已校验证据
     * @throws net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectedException
     *         确定性 Profile 策略拒绝（不可重试）
     * @throws net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceRejectedException
     *         状态类拒绝（过期/吊销/链不可信等，保持既有表面）
     * @throws net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException
     *         材料源/依赖暂不可用（可重试）
     * @throws net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileVerificationUnavailableException
     *         Profile 验证能力未装配
     */
    ValidatedTboxDeviceCertificate validate(DeviceCertificateRef ref, DeviceCertificateProfile profile);
}
