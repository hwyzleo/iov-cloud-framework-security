package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 业务类型枚举（硬编码）
 * <p>
 * 单一枚举承载业务类型唯一性、器件类别与<strong>能力声明</strong>（supportsData + prov）。
 * <p>
 * 以能力声明取代原单值 {@code kind}：{@code supportsData} 与 {@code prov} 相互独立，
 * 一个业务可同时支持 DATA（信封加解密）与 PROVISION（派生/封装）。
 * 各 PROVISION 业务各自携带 {@code keyName}（不同业务不同 keyName → 不同秘密）
 * 与 {@code anchor}（声明车级/设备级），不引入 {@code PER_DEVICE_CONST}。
 */
public enum BizType {

    /**
     * 车云通信根
     */
    V2C_COMM_ROOT(DeviceCategory.TBOX, false, new Prov("v2c-comm-root", Anchor.VEHICLE)),
    /**
     * 防盗组密钥
     */
    IMMO_GROUP_KEY(DeviceCategory.BCM, false, new Prov("immo-group", Anchor.VEHICLE)),
    /**
     * TBOX设备根
     */
    TBOX_DEVICE_ROOT(DeviceCategory.TBOX, false, new Prov("tbox-dev-root", Anchor.DEVICE)),
    /**
     * 中央网关设备根
     */
    CGW_DEVICE_ROOT(DeviceCategory.CGW, false, new Prov("cgw-dev-root", Anchor.DEVICE)),
    /**
     * 自动驾驶域控设备根
     */
    AD_DCU_DEVICE_ROOT(DeviceCategory.AD_DCU, false, new Prov("ad-dcu-dev-root", Anchor.DEVICE)),
    /**
     * 座舱域控设备根
     */
    CPT_DCU_DEVICE_ROOT(DeviceCategory.CPT_DCU, false, new Prov("cpt-dcu-dev-root", Anchor.DEVICE)),
    /**
     * 智能钥匙设备根
     */
    PEPS_DEVICE_ROOT(DeviceCategory.PEPS, false, new Prov("peps-dev-root", Anchor.DEVICE)),
    /**
     * 安全灌注机设备根（产线工装；防盗根等封装下发的收方；仅 uid 路径）
     */
    KLD_DEVICE_ROOT(DeviceCategory.KLD, false, new Prov("kld-dev-root", Anchor.DEVICE));

    private final DeviceCategory deviceCategory;
    private final boolean supportsData;
    private final Prov prov;

    BizType(DeviceCategory deviceCategory, boolean supportsData, Prov prov) {
        this.deviceCategory = deviceCategory;
        this.supportsData = supportsData;
        this.prov = prov;
    }

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
     * 派生/封装能力声明（非空 = 可走派生/封装，携带 keyName + anchor）
     *
     * @return Prov 或 null（不支持派生/封装时）
     */
    public Prov prov() {
        return prov;
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
     * 秘密锚定层级：VEHICLE = 绑 VIN（换件不变/可车内多件同值），DEVICE = 绑芯片（随件）
     */
    public enum Anchor {
        VEHICLE,
        DEVICE
    }

    /**
     * 派生/封装能力声明
     *
     * @param keyName KMS 命名密钥名（不同业务不同 keyName → 不同秘密）
     * @param anchor  锚定层级（VEHICLE / DEVICE）
     */
    public record Prov(String keyName, Anchor anchor) {
    }
}
