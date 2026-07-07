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
     * 远程控制（仅数据加密）
     */
    REMOTE_CONTROL(DeviceCategory.TBOX, true, null),

    /**
     * SecOC 组密钥（仅派生，车级锚定——绑 VIN，换 TBOX 不变）
     */
    SECOC_GROUP(DeviceCategory.TBOX, false, new Prov("secoc-master", Anchor.VEHICLE)),

    /**
     * 设备根密钥（仅派生，设备级锚定——绑芯片 UID）
     */
    DEVICE_ROOT(DeviceCategory.TBOX, false, new Prov("dev-root-master", Anchor.DEVICE)),

    /**
     * 遥测（数据加密 + 派生，设备级锚定——两用）
     */
    TELEMETRY(DeviceCategory.TBOX, true, new Prov("telemetry-root", Anchor.DEVICE));

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
        TBOX
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
