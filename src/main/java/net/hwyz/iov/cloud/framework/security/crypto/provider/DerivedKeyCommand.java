package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;

import java.util.Objects;

/**
 * 受信派生命令（FW-SEC-DSN-CR-019 §5.1）。
 * <p>
 * 由 {@code KeyProvisioningTemplate.deriveAndWrap} 内部转换而来：调用方字段只表达业务锚、
 * purpose、收方（已验证证据）与操作上下文；rootRef、Transit 路径、派生标签与算法由
 * {@link DerivedKeyPolicyRegistry} 补全，请求<strong>不得覆盖</strong>根名或算法。
 *
 * @param bizType              业务类型（必须 {@code materialModel == DERIVED_ROOT}）
 * @param anchor               派生锚点（规范化原文 + 摘要）
 * @param purpose              受治理派生用途
 * @param recipient            已验证收方证书证据（两级校验后的不可变结果）
 * @param context              派生上下文（派生版本/业务版本）
 * @param operation            写操作上下文（operationId/幂等键）
 * @param protocolRequestId    协议层请求标识（车云协议 keyprov requestId，供 AAD/HKDF 使用；
 *                             与收方证书 enrollment requestId 语义不同，禁止混用）
 * @param protocolBusinessDomain 协议层业务域（如 V2C_COMM；区别于 KMS 材料 BizType.name()）
 */
public record DerivedKeyCommand(
        BizType bizType,
        KeyAnchor anchor,
        KeyPurpose purpose,
        ValidatedRecipientEvidence recipient,
        DerivationContext context,
        OperationContext operation,
        String protocolRequestId,
        String protocolBusinessDomain) {

    public DerivedKeyCommand {
        Objects.requireNonNull(bizType, "bizType must not be null");
        Objects.requireNonNull(anchor, "anchor must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(recipient, "recipient must not be null");
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(operation, "operation must not be null");
        Objects.requireNonNull(protocolRequestId, "protocolRequestId must not be null");
        Objects.requireNonNull(protocolBusinessDomain, "protocolBusinessDomain must not be null");
        if (protocolRequestId.isBlank()) {
            throw new IllegalArgumentException("protocolRequestId must not be blank");
        }
        if (protocolBusinessDomain.isBlank()) {
            throw new IllegalArgumentException("protocolBusinessDomain must not be blank");
        }
    }
}
