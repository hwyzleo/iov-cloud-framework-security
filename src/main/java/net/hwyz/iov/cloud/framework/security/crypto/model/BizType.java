package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 业务类型枚举（硬编码）
 * <p>
 * 单一枚举承载业务类型唯一性、器件类别与<strong>能力声明</strong>。
 * 能力声明分两组，相互独立：
 * <ul>
 *   <li><strong>对称侧</strong>：{@code supportsData}（信封加解密）、{@code prov}（派生/封装）、{@code cryptoMode}（ENVELOPE/SESSION）</li>
 *   <li><strong>非对称侧</strong>：{@code keyType}（SYMMETRIC/ASYMMETRIC）、{@code supportsSigning}（签名/验签）、{@code signAlgo}（签名算法）</li>
 * </ul>
 * 各 PROVISION/SIGNING 业务各自携带 {@code keyName}（不同业务不同 keyName -> 不同秘密）
 * 与 {@code anchor}（声明车级/设备级/组织级），不引入 {@code PER_DEVICE_CONST}。
 */
public enum BizType {

    /**
     * 车云通信根
     */
    V2C_COMM_ROOT(DeviceCategory.TBOX, false, new Prov("v2c-comm-root", Anchor.VEHICLE), CryptoMode.SESSION,
            KeyType.SYMMETRIC, false, null),
    /**
     * 防盗组密钥
     */
    IMMO_GROUP_KEY(DeviceCategory.BCM, false, new Prov("immo-group", Anchor.VEHICLE), CryptoMode.ENVELOPE,
            KeyType.SYMMETRIC, false, null),
    /**
     * OTA车辆侧激活/回执根
     */
    OTA_VEHICLE_ROOT(DeviceCategory.CGW, false, new Prov("ota-vehicle-root", Anchor.VEHICLE), CryptoMode.ENVELOPE,
            KeyType.SYMMETRIC, false, null),
    /**
     * TBOX设备根
     */
    TBOX_DEVICE_ROOT(DeviceCategory.TBOX, false, new Prov("tbox-dev-root", Anchor.DEVICE), CryptoMode.ENVELOPE,
            KeyType.SYMMETRIC, false, null),
    /**
     * 中央网关设备根
     */
    CGW_DEVICE_ROOT(DeviceCategory.CGW, false, new Prov("cgw-dev-root", Anchor.DEVICE), CryptoMode.ENVELOPE,
            KeyType.SYMMETRIC, false, null),
    /**
     * 自动驾驶域控设备根
     */
    AD_DCU_DEVICE_ROOT(DeviceCategory.AD_DCU, false, new Prov("ad-dcu-dev-root", Anchor.DEVICE), CryptoMode.ENVELOPE,
            KeyType.SYMMETRIC, false, null),
    /**
     * 座舱域控设备根
     */
    CPT_DCU_DEVICE_ROOT(DeviceCategory.CPT_DCU, false, new Prov("cpt-dcu-dev-root", Anchor.DEVICE), CryptoMode.ENVELOPE,
            KeyType.SYMMETRIC, false, null),
    /**
     * 智能钥匙设备根
     */
    PEPS_DEVICE_ROOT(DeviceCategory.PEPS, false, new Prov("peps-dev-root", Anchor.DEVICE), CryptoMode.ENVELOPE,
            KeyType.SYMMETRIC, false, null),
    /**
     * 安全灌注机设备根（产线工装；防盗根等封装下发的收方；仅 uid 路径）
     */
    KLD_DEVICE_ROOT(DeviceCategory.KLD, false, new Prov("kld-dev-root", Anchor.DEVICE), CryptoMode.ENVELOPE,
            KeyType.SYMMETRIC, false, null),
    /**
     * 数字钥匙 KTS 签名私钥（车企 KTS 侧签名根，云端持有，组织级全局一把）
     * <p>
     * 首个非对称签名消费方（IDK / CCC），具体业务用途归消费方定义。
     * {@code anchor=ORG}：{@code KeyScope.org()} 无需附带主体，KMS keyName 即 {@code prov.keyName}。
     */
    IDK_KTS_SIGNING(null, false, new Prov("idk-kts-signing", Anchor.ORG), null,
            KeyType.ASYMMETRIC, true, SignAlgo.ECDSA_P256);

    private final DeviceCategory deviceCategory;
    private final boolean supportsData;
    private final Prov prov;
    private final CryptoMode cryptoMode;
    private final KeyType keyType;
    private final boolean supportsSigning;
    private final SignAlgo signAlgo;

    BizType(DeviceCategory deviceCategory, boolean supportsData, Prov prov, CryptoMode cryptoMode,
            KeyType keyType, boolean supportsSigning, SignAlgo signAlgo) {
        this.deviceCategory = deviceCategory;
        this.supportsData = supportsData;
        this.prov = prov;
        this.cryptoMode = cryptoMode;
        this.keyType = keyType;
        this.supportsSigning = supportsSigning;
        this.signAlgo = signAlgo;
    }

    /**
     * 器件类别（ORG 锚定的非对称密钥可为 null）
     *
     * @return DeviceCategory 或 null
     */
    public DeviceCategory getDeviceCategory() {
        return deviceCategory;
    }

    /**
     * 是否支持信封加解密（{@code CryptoTemplate.encrypt/decrypt}）
     *
     * @return true 表示可走信封加解密
     */
    public boolean supportsData() {
        return supportsData;
    }

    /**
     * 是否支持派生/封装（{@code KeyProvisioningTemplate} 各方法）
     *
     * @return true 表示 prov 非空，可走派生/封装
     */
    public boolean supportsProvision() {
        return prov != null;
    }

    /**
     * 派生/封装/签名能力声明（非空 = 携带 keyName + anchor，可走派生/封装或签名/验签）
     *
     * @return Prov 或 null
     */
    public Prov prov() {
        return prov;
    }

    /**
     * 加解密模型分派（ENVELOPE 信封 DEK / SESSION 会话根 KDF）
     * <p>
     * 仅对称密钥适用；非对称-only 项为 null。
     *
     * @return CryptoMode 或 null
     */
    public CryptoMode cryptoMode() {
        return cryptoMode;
    }

    /**
     * 密钥类型（SYMMETRIC / ASYMMETRIC）
     *
     * @return KeyType
     */
    public KeyType keyType() {
        return keyType;
    }

    /**
     * 是否支持非对称签名/验签（{@code SigningTemplate}）
     *
     * @return true 表示可走签名/验签
     */
    public boolean supportsSigning() {
        return supportsSigning;
    }

    /**
     * 签名算法声明（仅 supportsSigning=true 时有意义）
     *
     * @return SignAlgo 或 null
     */
    public SignAlgo signAlgo() {
        return signAlgo;
    }

    /**
     * 根据名称查找 BizType
     *
     * @param name 业务类型名称
     * @return BizType 枚举值
     * @throws IllegalArgumentException 如果名称不存在
     */
    public static BizType fromName(String name) {
        for (BizType type : values()) {
            if (type.name().equals(name)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown BizType: " + name);
    }

    /**
     * 器件类别
     */
    public enum DeviceCategory {
        TBOX,
        CGW,
        AD_DCU,
        CPT_DCU,
        PEPS,
        BCM,
        KLD
    }

    /**
     * 秘密锚定层级：
     * <ul>
     *   <li>VEHICLE = 绑 VIN（换件不变/可车内多器件同值）</li>
     *   <li>DEVICE = 绑芯片（随件）</li>
     *   <li>ORG = 组织级（全局一把，如 KTS 签名根；KeyScope.org() 无需主体）</li>
     * </ul>
     */
    public enum Anchor {
        VEHICLE,
        DEVICE,
        ORG,
        USER
    }

    /**
     * 派生/封装/签名能力声明
     *
     * @param keyName KMS 命名密钥名（不同业务不同 keyName -> 不同秘密）
     * @param anchor  锚定层级（VEHICLE / DEVICE / ORG）
     */
    public record Prov(String keyName, Anchor anchor) {
    }

    /**
     * 加解密模型：ENVELOPE=信封 DEK（KMS 取钥）；SESSION=会话根 KDF（本地派生会话密钥、不查 KMS）
     */
    public enum CryptoMode {
        ENVELOPE,
        SESSION
    }

    /**
     * 密钥类型：SYMMETRIC=对称（HMAC/AES）；ASYMMETRIC=非对称（ECDSA/EdDSA/RSA）
     */
    public enum KeyType {
        SYMMETRIC,
        ASYMMETRIC
    }

    /**
     * 签名算法（非对称密钥声明，与 KMS 原语对应）
     */
    public enum SignAlgo {
        /** ECDSA with P-256 / SHA-256, DER-encoded */
        ECDSA_P256,
        /** EdDSA with Ed25519 */
        EDDSA_ED25519
    }
}
