package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 设备证书 Profile（FW-SEC-DSN-CR-017 §1/§4）。
 * <p>
 * 版本化、受治理的证书策略档。作为 CR-014（ECDH-ES 封装收方）与 CR-016（Import Attestation
 * 验签证书）的<strong>共同证书事实源</strong>：两条路径必须解析并验证同一 Profile、共享同一
 * {@code DeviceCertificateRef} 与 leaf DER 摘要语义。
 * <p>
 * 首期仅 {@link #TBOX_DEVICE_ECDH_ES_P256_V1}：EC P-256、CA=false、
 * KU=digitalSignature+keyAgreement、EKU=仅 clientAuth。新增 Profile 走 CR + framework 发版。
 */
public enum DeviceCertificateProfile {

    /**
     * TBOX ECDH-ES P-256 统一设备证书 Profile v1（FW-SEC-DSN-CR-017 RD-017-1）。
     * <p>
     * 固定约束：叶子（CA=false）、公钥 EC NIST P-256、KeyUsage 同时含
     * {@code digitalSignature + keyAgreement}、EKU allowlist 仅为 {@code clientAuth}、
     * 无未知关键扩展，且 subject 携带设备身份。
     */
    TBOX_DEVICE_ECDH_ES_P256_V1
}
