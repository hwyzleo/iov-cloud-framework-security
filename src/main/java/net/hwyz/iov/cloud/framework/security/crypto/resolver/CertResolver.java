package net.hwyz.iov.cloud.framework.security.crypto.resolver;

/**
 * 证书解析器 SPI（由 PKI / 证书目录实现）
 * <p>
 * 把主体（VIN / device_sn / UID / certSerial）解析为收方证书 DER，
 * 供 {@code CertEncryptionTemplate} 在本地完成加密。
 * <p>
 * <strong>解析与信任判定 / 链校验归 PKI</strong>，门面只做「给定合法公钥 -> 加密」的密码学运算。
 * framework 不自带证书目录，默认实现 {@code DefaultCertResolver} 为 fail-closed 桩。
 */
public interface CertResolver {

    /**
     * 按 VIN 解析收方证书
     *
     * @param vin VIN
     * @return 证书 DER 编码
     */
    byte[] resolveByVin(String vin);

    /**
     * 按设备 SN 解析收方证书
     *
     * @param deviceSn 设备 SN
     * @return 证书 DER 编码
     */
    byte[] resolveByDeviceSn(String deviceSn);

    /**
     * 按 UID 解析收方证书
     *
     * @param uid 用户唯一标识
     * @return 证书 DER 编码
     */
    byte[] resolveByUid(String uid);

    /**
     * 按证书序列号解析收方证书
     *
     * @param certSerial 证书序列号
     * @return 证书 DER 编码
     */
    byte[] resolveBySerial(String certSerial);
}
