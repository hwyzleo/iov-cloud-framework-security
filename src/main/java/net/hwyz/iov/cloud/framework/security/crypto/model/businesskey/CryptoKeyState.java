package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;

/**
 * 密码学状态（FW-SEC-DSN-CR-009）。
 * <p>
 * 材料/目录返回的密码学与业务状态统一口径：
 * <ul>
 *   <li>ACTIVE：当前活跃（唯一，供 resolveActive 寻址）</li>
 *   <li>DEPRECATED：已轮换，处于 VMD 维护的解密窗口内</li>
 *   <li>REVOKED：已吊销，拒绝一切使用</li>
 *   <li>EXPIRED：已过期，拒绝一切使用</li>
 * </ul>
 */
public enum CryptoKeyState {
    ACTIVE,
    DEPRECATED,
    REVOKED,
    EXPIRED
}
