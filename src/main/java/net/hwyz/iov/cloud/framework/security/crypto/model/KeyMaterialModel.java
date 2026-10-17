package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 业务密钥材料模型（FW-SEC-DSN-CR-013 §7.1）。
 * <p>
 * 受治理的类型分类，随 {@link BizType} 一并治理，禁止依据方法调用动态猜测：
 * <ul>
 *   <li>{@link #DERIVED_ROOT}：根派生型。由 Transit/HSM 受治理根按规范化锚、
 *       {@link KeyPurpose} 与派生版本确定性生成，并在受控边界内原子封装；
 *       由 {@code KeyProvisioningTemplate.deriveAndWrap} 承接。</li>
 *   <li>{@link #RANDOM_MATERIAL}：独立随机材料型。由 Provider 生成并密封保存，
 *       按显式 keyRef 管理；由 {@code BusinessKeyMaterialTemplate} 承接。</li>
 * </ul>
 * 两者不得隐式互相回退；路由不匹配时 fail-closed。
 */
public enum KeyMaterialModel {
    /** 根派生型：Transit/HSM 根派生 + 受控封装（V2C_COMM_ROOT、各 *_DEVICE_ROOT 等） */
    DERIVED_ROOT,
    /** 独立随机材料型：Provider 生成/保存，按显式 keyRef 管理 */
    RANDOM_MATERIAL
}
