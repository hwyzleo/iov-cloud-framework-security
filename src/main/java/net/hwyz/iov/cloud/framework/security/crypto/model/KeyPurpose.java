package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 根派生密钥用途（FW-SEC-DSN-CR-013 §6）。
 * <p>
 * 受治理的封闭集合，业务不得传入任意自由字符串；用于派生上下文的域隔离，
 * 同一锚点、同一根版本、同一派生版本下，不同 purpose 必须得到不同结果。
 * <p>
 * 首期仅登记 AEAD 上/下行两类。新增取值走 CR + framework 发版。
 * <p>
 * <strong>canonical 数值（FW-SEC-DSN-CR-016 §3 / TBOX-SEC-DSN-CR-020 §7.3）</strong>：
 * {@link #canonicalValue()} 为导入证明 proofInput 提供稳定、跨语言的 purpose 编码。
 * 数值 {@code 0} 保留给协议层 {@code UNSPECIFIED}，Java 领域模型不得构造该状态；
 * <strong>禁止</strong>使用 {@code ordinal()}、{@code name()} 或枚举声明顺序参与 canonical 编码。
 * 已发布数值不得修改或复用，新增 purpose 必须显式分配新值。
 */
public enum KeyPurpose {
    /** 上行 AEAD 材料（设备 → 云） */
    UPLINK_AEAD(1),
    /** 下行 AEAD 材料（云 → 设备） */
    DOWNLINK_AEAD(2);

    private final int canonicalValue;

    KeyPurpose(int canonicalValue) {
        this.canonicalValue = canonicalValue;
    }

    /**
     * 稳定的 canonical / wire 数值（UPLINK_AEAD=1、DOWNLINK_AEAD=2；0 保留给 UNSPECIFIED）。
     * <p>
     * 禁止以 {@code ordinal()} 或 {@code name()} 替代本值参与 canonical 编码。
     *
     * @return canonical 数值
     */
    public int canonicalValue() {
        return canonicalValue;
    }
}
