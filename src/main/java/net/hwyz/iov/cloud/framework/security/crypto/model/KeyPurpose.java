package net.hwyz.iov.cloud.framework.security.crypto.model;

/**
 * 根派生密钥用途（FW-SEC-DSN-CR-013 §6）。
 * <p>
 * 受治理的封闭集合，业务不得传入任意自由字符串；用于派生上下文的域隔离，
 * 同一锚点、同一根版本、同一派生版本下，不同 purpose 必须得到不同结果。
 * <p>
 * 首期仅登记 AEAD 上/下行两类。新增取值走 CR + framework 发版。
 */
public enum KeyPurpose {
    /** 上行 AEAD 材料（设备 → 云） */
    UPLINK_AEAD,
    /** 下行 AEAD 材料（云 → 设备） */
    DOWNLINK_AEAD
}
