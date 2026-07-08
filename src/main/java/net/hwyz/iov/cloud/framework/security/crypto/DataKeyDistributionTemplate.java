package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceRecipient;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedDataKey;

/**
 * 活跃数据密钥·设备封装在线下发门面 API（CR-005）
 * <p>
 * 受 {@code crypto.keyprov.enabled} 条件装配，仅下发编排方（如 VAGW）启用。
 * 校验 {@code bizType.supportsData == true}（对称于 {@link CryptoTemplate}，而非 {@code prov != null}），
 * 否则 fail-closed。
 * <p>
 * 取 {@code (device_sn, 业务域)} 活跃 DATA 密钥、用收方设备公钥/证书封装下发；密钥明文不出 KMS。
 * 同 {@code (device_sn, 业务域, 用途)} 有效期内幂等返回同一活跃 keyId。
 */
public interface DataKeyDistributionTemplate {

    /**
     * 取活跃数据密钥并用设备公钥/证书封装下发
     *
     * @param deviceSnOrVin 设备 SN 或 VIN（VIN 需先解析为 device_sn）
     * @param bizType       业务类型（须 supportsData==true）
     * @param recipient     收方设备（certSerial）
     * @return 设备公钥封装的活跃数据密钥
     */
    WrappedDataKey issueActiveKeyForDevice(String deviceSnOrVin, BizType bizType, DeviceRecipient recipient);
}
