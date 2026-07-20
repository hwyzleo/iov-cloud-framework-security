package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.time.Instant;
import java.util.Objects;

/**
 * 证书申请结果
 *
 * @param requestId    请求 ID（稳定标识）
 * @param state        注册状态
 * @param submittedAt  提交时间
 */
public record CertApplyResult(

        String requestId,

        EnrollmentState state,

        Instant submittedAt
) {

    public CertApplyResult {
        Objects.requireNonNull(requestId, "requestId must not be null");
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(submittedAt, "submittedAt must not be null");
    }
}
