package net.hwyz.iov.cloud.framework.security.crypto.transit;

/**
 * OpenBao 系统健康快照（FW-SEC-DSN-CR-019 §10 readiness 维度 1）。
 *
 * @param initialized 是否已初始化
 * @param sealed      是否 sealed
 * @param standby     是否 standby（非 active）
 */
public record TransitSystemHealth(boolean initialized, boolean sealed, boolean standby) {

    public boolean ready() {
        return initialized && !sealed && !standby;
    }
}
