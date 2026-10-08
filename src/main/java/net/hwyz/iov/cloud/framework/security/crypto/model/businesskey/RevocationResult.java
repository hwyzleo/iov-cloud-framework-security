package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.time.Instant;

/**
 * 吊销结果（FW-SEC-DSN-CR-009 §3）。
 *
 * @param keyId     被吊销材料标识
 * @param state     吊销后的密码学状态
 * @param changedAt 变更时间
 */
public record RevocationResult(String keyId, CryptoKeyState state, Instant changedAt) implements Serializable {
}
