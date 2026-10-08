package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

/**
 * 吊销请求（FW-SEC-DSN-CR-009 §3）。
 *
 * @param reason         吊销原因
 * @param idempotencyKey 幂等键（结果未知时须使用原键对账）
 */
public record RevocationRequest(String reason, String idempotencyKey) implements Serializable {

    public RevocationRequest {
        Objects.requireNonNull(idempotencyKey, "idempotencyKey must not be null");
    }
}
