package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;

/**
 * KMS客户端接口
 */
public interface KmsClient {

    /**
     * 创建业务密钥材料（FW-SEC-DSN-CR-009 §9）。
     * <p>
     * 仅创建材料，不决定业务 ACTIVE（由 VMD 目录权威决定）。
     * 结果未知（请求已发送但无法确认）时抛
     * {@link net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException}；
     * 幂等冲突抛 {@link net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyIdempotencyConflictException}。
     *
     * @param command 创建命令
     * @return 创建的材料
     */
    KmsKeyMaterial createDataKey(KmsCreateKeyCommand command);

    /**
     * 按显式 keyRef 向显式收方封装（FW-SEC-DSN-CR-009 §9）。
     * <p>
     * 无隐式收方推断；DEVICE_ROOT_KEK 仅在显式可信 wrappingKeyRef 下可用。
     *
     * @param keyRef    显式密钥引用
     * @param recipient 显式收方
     * @return 瞬时封装结果
     */
    KmsWrappedKey wrapKey(KmsKeyReference keyRef, KmsRecipient recipient);

    /**
     * 查询显式 keyRef 的材料元数据（FW-SEC-DSN-CR-009 §9）。
     *
     * @param keyRef 显式密钥引用
     * @return 材料元数据（含密码学状态）
     */
    KmsKeyMetadata getKeyMetadata(KmsKeyReference keyRef);

    /**
     * 按显式 keyRef 吊销（幂等，FW-SEC-DSN-CR-009 §9）。
     *
     * @param keyRef         显式密钥引用
     * @param reason         吊销原因
     * @param idempotencyKey 幂等键
     * @return 吊销结果（密码学状态）
     */
    KmsRevocationResult revokeKey(KmsKeyReference keyRef, String reason, String idempotencyKey);

    /**
     * 获取活跃数据密钥
     *
     * @param keyName 密钥名称
     * @param bizType 业务类型
     * @return 包装密钥
     * @deprecated 由 FW-SEC-DSN-CR-009 取代：framework 不再按 deviceSn+BizType 直接选活跃 key；
     * 请经 {@link net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyDirectoryResolver} 寻址 + 
     * {@link net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyMaterialTemplate} 材料门面。
     */
    @Deprecated
    WrappedKey getActiveDataKey(String keyName, BizType bizType);

    /**
     * 根据keyId获取历史数据密钥
     *
     * @param keyName 密钥名称
     * @param keyId   密钥ID
     * @return 包装密钥
     */
    WrappedKey getDataKeyById(String keyName, String keyId);

    /**
     * 解封包装密钥
     *
     * @param keyName 密钥名称
     * @param wrapped 包装密钥
     * @return 明文DEK
     */
    byte[] unwrap(String keyName, WrappedKey wrapped);

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
     * @param keyName   密钥名称
     * @param deviceSn  设备 SN
     * @param bizType   业务类型（须 supportsData==true）
     * @param certSerial 收方设备证书序列号
     * @return 设备公钥封装的活跃数据密钥
     * @deprecated 由 FW-SEC-DSN-CR-009 取代：内部按 deviceSn+BizType 选活跃 key 的口径不再保留，
     * 兼容层必须委托 {@link net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyDirectoryResolver}。
     */
    @Deprecated
    WrappedDataKey wrapActiveDataKeyForDevice(String keyName, String deviceSn, BizType bizType, String certSerial);

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
