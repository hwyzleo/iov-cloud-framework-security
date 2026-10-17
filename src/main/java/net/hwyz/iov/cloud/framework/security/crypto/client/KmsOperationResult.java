package net.hwyz.iov.cloud.framework.security.crypto.client;

/**
 * 业务密钥 Provider 操作对账结果（FW-SEC-DSN-CR-011 §6.5）。
 * <p>
 * 仅承载非敏感信息：operationId、状态、非敏感结果引用与摘要性 message。
 * 不得包含密钥材料、Provider 密封密文或完整收方信息。
 *
 * @param operationId 客户端生成的 UUIDv7 操作标识
 * @param state       操作状态
 * @param resultRef   非敏感结果引用（如 keyId/kmsKeyRef；无则为 null）
 * @param message     非敏感摘要说明
 */
public record KmsOperationResult(
        String operationId,
        KmsOperationState state,
        String resultRef,
        String message) {

    public boolean succeeded() {
        return state == KmsOperationState.SUCCEEDED;
    }

    public boolean pendingOrUnknown() {
        return state == KmsOperationState.PENDING || state == KmsOperationState.UNKNOWN;
    }
}
