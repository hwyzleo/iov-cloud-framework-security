package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;

import java.time.Instant;

/**
 * KMS 吊销结果（FW-SEC-DSN-CR-009 §9）。
 *
 * @param keyId     被吊销材料标识
 * @param state     吊销后状态
 * @param changedAt 变更时间
 */
public record KmsRevocationResult(String keyId, CryptoKeyState state, Instant changedAt) {
}
