package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyScope;

/**
 * 通用非对称签名 / 验签门面 API（CR-006）
 * <p>
 * 以 KMS 托管的非对称私钥完成签名与验签；私钥永不出 KMS。业务无关--按
 * {@code BizType} + {@code KeyScope} 定位密钥，不含任何具体场景逻辑。
 * <p>
 * 受 {@code crypto.signing.enabled} 条件装配，仅签名 / 验签消费方启用。
 * <p>
 * <strong>密钥定位 = BizType + KeyScope</strong>：{@code BizType} 给出密钥模板
 * （{@code prov.keyName}）与锚定维度（{@code prov.anchor}）；{@code KeyScope} 提供
 * VIN / UID / device / org() 具体值，二者拼出唯一 KMS keyName。
 * 校验：{@code bizType.supportsSigning == true}、{@code keyType == ASYMMETRIC}，
 * 且 {@code KeyScope} 类型与 {@code bizType.prov.anchor} 匹配，否则 fail-closed。
 */
public interface SigningTemplate {

    /**
     * 我方签名：bizType 定位密钥模板 + anchor，scope 提供 VIN/UID/device/org() 具体值
     *
     * @param bizType 业务类型（须 supportsSigning=true, keyType=ASYMMETRIC）
     * @param scope   密钥作用域（须与 bizType.prov.anchor 匹配）
     * @param data    被签数据
     * @return 签名值（DER 编码）
     */
    byte[] sign(BizType bizType, KeyScope scope, byte[] data);

    /**
     * 取我方公钥 / 证书（供下发或对端校验）
     *
     * @param bizType 业务类型
     * @param scope   密钥作用域
     * @return 公钥 SPKI DER 或证书 DER
     */
    byte[] getPublicKey(BizType bizType, KeyScope scope);

    /**
     * 验我方签名
     *
     * @param bizType   业务类型
     * @param scope     密钥作用域
     * @param data      被签数据
     * @param signature 签名值
     * @return true 表示验签通过
     */
    boolean verify(BizType bizType, KeyScope scope, byte[] data, byte[] signature);

    /**
     * 验对方签名：用给定 / 解析到的对方证书或公钥
     * <p>
     * 证书信任判定 / 链校验归 PKI，本方法只做密码学验签。
     *
     * @param certOrPublicKey 对方证书 DER 或公钥 SPKI DER
     * @param data            被签数据
     * @param signature       签名值
     * @return true 表示验签通过
     */
    boolean verifyWith(byte[] certOrPublicKey, byte[] data, byte[] signature);
}
