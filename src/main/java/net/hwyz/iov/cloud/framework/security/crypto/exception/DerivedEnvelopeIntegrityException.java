package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 信封结构/摘要完整性校验失败（FW-SEC-DSN-CR-015 §4.3）。
 * <p>
 * 由公开 {@code DerivedEnvelopeDigestVerifier.verify(DerivedWrappedKeyEnvelopeView)} 在
 * 未知 format/version、必填字段缺失、长度非法或摘要不匹配时抛出；调用方
 * <strong>不得</strong>以返回值忽略完整性失败（API 无布尔返回）。
 * <p>
 * 属确定性失败（{@link #isRetryable()} 恒 {@code false}）：不得重试、不得回退解析私有
 * {@code envelopeBytes}，对应 capability/readiness 直接 DOWN。
 */
public class DerivedEnvelopeIntegrityException extends CryptoException {

    public DerivedEnvelopeIntegrityException(String message) {
        super(Reason.INTEGRITY_VERIFICATION_FAILED, message);
    }

    public DerivedEnvelopeIntegrityException(String message, Throwable cause) {
        super(Reason.INTEGRITY_VERIFICATION_FAILED, message, cause);
    }

    @Override
    public boolean isRetryable() {
        return false;
    }
}
