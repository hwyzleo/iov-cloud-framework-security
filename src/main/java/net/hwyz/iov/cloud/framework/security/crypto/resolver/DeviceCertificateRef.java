package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 证书引用 / 证据输入（FW-SEC-DSN-CR-012 §5）。
 * <p>
 * 与 {@code RecipientRef.DeviceCertificate} 对应，但归属「解析输入」而非「封装收方」：
 * 调用方可按所持证据构造（仅有 serial、仅有 requestId、已持 DER/SPKI，或仅有主体），
 * framework 默认解析器据此按证据优先级编排来源。
 * <p>
 * 安全关键主体使用显式 {@link CertificateSubjectRef}；{@code context} 仅承载
 * 不参与安全决策的扩展信息（如 profile/issuer 提示），<b>不</b>得用于传递主体身份。
 *
 * @param certSerial        证书序列号（可空）
 * @param requestId         证书注册 requestId（可空）
 * @param certificateDer    叶子证书 DER（可空）
 * @param spki              收方公钥 SPKI DER（可空）
 * @param sha256Fingerprint 期望 SHA-256 指纹（仅固定/比对，可空；不能替代 DER/SPKI）
 * @param subject           安全关键主体（可空）
 * @param context           非安全扩展上下文（可空）
 */
public record DeviceCertificateRef(
        String certSerial,
        String requestId,
        byte[] certificateDer,
        byte[] spki,
        String sha256Fingerprint,
        CertificateSubjectRef subject,
        Map<String, String> context
) implements Serializable {

    public DeviceCertificateRef {
        certificateDer = certificateDer == null ? null : certificateDer.clone();
        spki = spki == null ? null : spki.clone();
        context = context == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(context));
    }

    public boolean hasInlineDer() {
        return certificateDer != null && certificateDer.length > 0;
    }

    public boolean hasInlineSpki() {
        return spki != null && spki.length > 0;
    }

    public static DeviceCertificateRef ofSerial(String certSerial) {
        return new DeviceCertificateRef(certSerial, null, null, null, null, null, null);
    }

    public static DeviceCertificateRef ofRequestId(String requestId) {
        return new DeviceCertificateRef(null, requestId, null, null, null, null, null);
    }

    public static DeviceCertificateRef ofCertificate(byte[] certificateDer) {
        return new DeviceCertificateRef(null, null, certificateDer, null, null, null, null);
    }

    public static DeviceCertificateRef ofSpki(byte[] spki) {
        return new DeviceCertificateRef(null, null, null, spki, null, null, null);
    }

    public static DeviceCertificateRef ofSubject(CertificateSubjectRef subject) {
        Objects.requireNonNull(subject, "subject must not be null");
        return new DeviceCertificateRef(null, null, null, null, null, subject, null);
    }

    public static DeviceCertificateRef ofSubjectAndSerial(CertificateSubjectRef subject, String certSerial) {
        return new DeviceCertificateRef(certSerial, null, null, null, null, subject, null);
    }

    /**
     * 便捷：附加期望指纹（返回新引用，不改动原引用）。
     */
    public DeviceCertificateRef withFingerprint(String fingerprint) {
        return new DeviceCertificateRef(certSerial, requestId, certificateDer, spki,
                fingerprint, subject, context);
    }
}
