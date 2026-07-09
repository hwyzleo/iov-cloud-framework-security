package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;

/**
 * KMS客户端接口
 */
public interface KmsClient {

    /**
     * 获取活跃数据密钥
     *
     * @param deviceSn 设备SN
     * @param bizType  业务类型
     * @return 包装密钥
     */
    WrappedKey getActiveDataKey(String deviceSn, BizType bizType);

    /**
     * 根据keyId获取历史数据密钥
     *
     * @param keyId 密钥ID
     * @return 包装密钥
     */
    WrappedKey getDataKeyById(String keyId);

    /**
     * 解封包装密钥
     *
     * @param wrapped 包装密钥
     * @return 明文DEK
     */
    byte[] unwrap(WrappedKey wrapped);

    /**
     * HMAC派生
     *
     * @param keyName 密钥名称（如oem-master）
     * @param input   输入数据
     * @return HMAC值
     */
    byte[] hmac(String keyName, byte[] input);

    /**
     * 命名密钥封装
     *
     * @param keyName   密钥名称（如KEK）
     * @param plaintext 明文
     * @return 密文
     */
    byte[] encryptWith(String keyName, byte[] plaintext);

    /**
     * 命名密钥解封
     *
     * @param keyName    密钥名称（如KEK）
     * @param ciphertext 密文
     * @return 明文
     */
    byte[] decryptWith(String keyName, byte[] ciphertext);

    /**
     * 取活跃 DATA 密钥并用设备公钥/证书封装下发（CR-005）
     * <p>
     * 密钥明文不出 KMS，返回设备公钥封装的密文。
     *
     * @param deviceSn    设备 SN
     * @param bizType     业务类型（须 supportsData==true）
     * @param certSerial  收方设备证书序列号
     * @return 设备公钥封装的活跃数据密钥
     */
    WrappedDataKey wrapActiveDataKeyForDevice(String deviceSn, BizType bizType, String certSerial);

    /**
     * 派生会话根（CR-005 SESSION 模式）
     * <p>
     * 按 keyName + VIN 取/派生会话根，供 HKDF 现算会话密钥。
     *
     * @param keyName 密钥名称（来自 bizType.prov.keyName）
     * @param vin     VIN
     * @return 会话根字节数组
     */
    byte[] deriveSessionRoot(String keyName, String vin);

    /**
     * KMS 内非对称签名（CR-006）
     * <p>
     * 私钥永不出 KMS，KMS 内部完成签名后返回签名值。
     *
     * @param keyName 密钥名称
     * @param data    被签数据
     * @param algo    签名算法
     * @return 签名值（DER 编码）
     */
    byte[] signWith(String keyName, byte[] data, BizType.SignAlgo algo);

    /**
     * KMS 内非对称验签（CR-006）
     *
     * @param keyName   密钥名称
     * @param data      被签数据
     * @param signature 签名值
     * @param algo      签名算法
     * @return true 表示验签通过
     */
    boolean verifyWith(String keyName, byte[] data, byte[] signature, BizType.SignAlgo algo);

    /**
     * 取 KMS 托管非对称密钥的公钥 / 证书（CR-006）
     *
     * @param keyName 密钥名称
     * @return 公钥 SPKI DER 或证书 DER
     */
    byte[] getPublicKey(String keyName);
}
