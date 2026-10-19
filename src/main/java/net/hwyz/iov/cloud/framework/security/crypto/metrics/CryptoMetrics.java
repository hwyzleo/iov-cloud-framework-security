package net.hwyz.iov.cloud.framework.security.crypto.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * 加解密指标收集
 */
@Component
public class CryptoMetrics {

    private final MeterRegistry meterRegistry;
    private final Counter encryptCounter;

    private final Counter decryptCounter;
    private final Counter kmsCallCounter;
    private final Counter errorCounter;
    private final Counter provisioningDeriveCounter;
    private final Counter provisioningWrapCounter;
    private final Counter provisioningUnwrapCounter;
    private final Counter keyprovIssueCounter;
    private final Counter sessionEncryptCounter;
    private final Counter sessionDecryptCounter;
    private final Counter signingSignCounter;
    private final Counter signingVerifyCounter;
    private final Counter certencEncryptCounter;
    private final Counter certencWrapKeyCounter;
    private final Counter certificateEnrollmentCounter;
    private final Counter certificateEnrollmentQueryCounter;
    private final Counter businessKeyCreateCounter;
    private final Counter businessKeyWrapCounter;
    private final Counter businessKeyMetadataCounter;
    private final Counter businessKeyRevokeCounter;
    private final Counter businessKeyDirectoryCounter;
    private final Counter importProofVerifyCounter;
    private final Counter importProofDependencyUnavailableCounter;
    private final Timer encryptTimer;
    private final Timer decryptTimer;
    private final Timer kmsCallTimer;
    private final Timer provisioningDeriveTimer;
    private final Timer provisioningWrapTimer;
    private final Timer provisioningUnwrapTimer;
    private final Timer keyprovIssueTimer;
    private final Timer sessionEncryptTimer;
    private final Timer sessionDecryptTimer;
    private final Timer signingSignTimer;
    private final Timer signingVerifyTimer;
    private final Timer certencEncryptTimer;
    private final Timer certencWrapKeyTimer;
    private final Timer certificateEnrollmentTimer;
    private final Timer certificateEnrollmentQueryTimer;
    private final Timer businessKeyCreateTimer;
    private final Timer businessKeyWrapTimer;
    private final Timer businessKeyMetadataTimer;
    private final Timer businessKeyRevokeTimer;
    private final Timer businessKeyDirectoryTimer;
    private final Timer importProofVerifyTimer;

    public CryptoMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.encryptCounter = Counter.builder("crypto.encrypt.count")
                .description("加密次数")
                .register(meterRegistry);

        this.decryptCounter = Counter.builder("crypto.decrypt.count")
                .description("解密次数")
                .register(meterRegistry);

        this.kmsCallCounter = Counter.builder("crypto.kms.call.count")
                .description("KMS调用次数")
                .register(meterRegistry);

        this.errorCounter = Counter.builder("crypto.error.count")
                .description("错误计数")
                .register(meterRegistry);

        this.provisioningDeriveCounter = Counter.builder("crypto.provisioning.derive.count")
                .description("派生次数")
                .register(meterRegistry);

        this.provisioningWrapCounter = Counter.builder("crypto.provisioning.wrap.count")
                .description("封装次数")
                .register(meterRegistry);

        this.provisioningUnwrapCounter = Counter.builder("crypto.provisioning.unwrap.count")
                .description("解封次数")
                .register(meterRegistry);

        this.keyprovIssueCounter = Counter.builder("crypto.keyprov.issue.count")
                .description("数据密钥下发次数")
                .register(meterRegistry);

        this.sessionEncryptCounter = Counter.builder("crypto.session.encrypt.count")
                .description("SESSION模式加密次数")
                .register(meterRegistry);

        this.sessionDecryptCounter = Counter.builder("crypto.session.decrypt.count")
                .description("SESSION模式解密次数")
                .register(meterRegistry);

        this.signingSignCounter = Counter.builder("crypto.signing.sign.count")
                .description("非对称签名次数")
                .register(meterRegistry);

        this.signingVerifyCounter = Counter.builder("crypto.signing.verify.count")
                .description("非对称验签次数")
                .register(meterRegistry);

        this.certencEncryptCounter = Counter.builder("crypto.certenc.encrypt.count")
                .description("证书加密次数")
                .register(meterRegistry);

        this.certencWrapKeyCounter = Counter.builder("crypto.certenc.wrapkey.count")
                .description("密钥封装次数")
                .register(meterRegistry);

        this.certificateEnrollmentCounter = Counter.builder("crypto.enrollment.submit.count")
                .description("证书申请提交次数")
                .register(meterRegistry);

        this.certificateEnrollmentQueryCounter = Counter.builder("crypto.enrollment.query.count")
                .description("证书申请查询次数")
                .register(meterRegistry);

        this.businessKeyCreateCounter = Counter.builder("crypto.business-key.create.count")
                .description("业务密钥材料创建次数")
                .register(meterRegistry);

        this.businessKeyWrapCounter = Counter.builder("crypto.business-key.wrap.count")
                .description("业务密钥封装次数")
                .register(meterRegistry);

        this.businessKeyMetadataCounter = Counter.builder("crypto.business-key.metadata.count")
                .description("业务密钥元数据查询次数")
                .register(meterRegistry);

        this.businessKeyRevokeCounter = Counter.builder("crypto.business-key.revoke.count")
                .description("业务密钥吊销次数")
                .register(meterRegistry);

        this.businessKeyDirectoryCounter = Counter.builder("crypto.business-key.directory.count")
                .description("业务密钥目录解析次数")
                .register(meterRegistry);

        this.importProofVerifyCounter = Counter.builder("crypto.import-proof.verify.count")
                .description("导入证明验签次数")
                .register(meterRegistry);

        this.importProofDependencyUnavailableCounter =
                Counter.builder("crypto.import-proof.dependency-unavailable.count")
                        .description("导入证明验签依赖/材料暂不可用次数")
                        .register(meterRegistry);

        this.encryptTimer = Timer.builder("crypto.encrypt.duration")
                .description("加密时延")
                .register(meterRegistry);

        this.decryptTimer = Timer.builder("crypto.decrypt.duration")
                .description("解密时延")
                .register(meterRegistry);

        this.kmsCallTimer = Timer.builder("crypto.kms.call.duration")
                .description("KMS调用时延")
                .register(meterRegistry);

        this.provisioningDeriveTimer = Timer.builder("crypto.provisioning.derive.duration")
                .description("派生时延")
                .register(meterRegistry);

        this.provisioningWrapTimer = Timer.builder("crypto.provisioning.wrap.duration")
                .description("封装时延")
                .register(meterRegistry);

        this.provisioningUnwrapTimer = Timer.builder("crypto.provisioning.unwrap.duration")
                .description("解封时延")
                .register(meterRegistry);

        this.keyprovIssueTimer = Timer.builder("crypto.keyprov.issue.duration")
                .description("数据密钥下发时延")
                .register(meterRegistry);

        this.sessionEncryptTimer = Timer.builder("crypto.session.encrypt.duration")
                .description("SESSION模式加密时延")
                .register(meterRegistry);

        this.sessionDecryptTimer = Timer.builder("crypto.session.decrypt.duration")
                .description("SESSION模式解密时延")
                .register(meterRegistry);

        this.signingSignTimer = Timer.builder("crypto.signing.sign.duration")
                .description("非对称签名时延")
                .register(meterRegistry);

        this.signingVerifyTimer = Timer.builder("crypto.signing.verify.duration")
                .description("非对称验签时延")
                .register(meterRegistry);

        this.certencEncryptTimer = Timer.builder("crypto.certenc.encrypt.duration")
                .description("证书加密时延")
                .register(meterRegistry);

        this.certencWrapKeyTimer = Timer.builder("crypto.certenc.wrapkey.duration")
                .description("密钥封装时延")
                .register(meterRegistry);

        this.certificateEnrollmentTimer = Timer.builder("crypto.enrollment.submit.duration")
                .description("证书申请提交时延")
                .register(meterRegistry);

        this.certificateEnrollmentQueryTimer = Timer.builder("crypto.enrollment.query.duration")
                .description("证书申请查询时延")
                .register(meterRegistry);

        this.businessKeyCreateTimer = Timer.builder("crypto.business-key.create.duration")
                .description("业务密钥材料创建时延")
                .register(meterRegistry);

        this.businessKeyWrapTimer = Timer.builder("crypto.business-key.wrap.duration")
                .description("业务密钥封装时延")
                .register(meterRegistry);

        this.businessKeyMetadataTimer = Timer.builder("crypto.business-key.metadata.duration")
                .description("业务密钥元数据查询时延")
                .register(meterRegistry);

        this.businessKeyRevokeTimer = Timer.builder("crypto.business-key.revoke.duration")
                .description("业务密钥吊销时延")
                .register(meterRegistry);

        this.businessKeyDirectoryTimer = Timer.builder("crypto.business-key.directory.duration")
                .description("业务密钥目录解析时延")
                .register(meterRegistry);

        this.importProofVerifyTimer = Timer.builder("crypto.import-proof.verify.duration")
                .description("导入证明验签时延")
                .register(meterRegistry);
    }

    /**
     * 记录加密操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordEncrypt(long duration) {
        encryptCounter.increment();
        encryptTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录解密操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordDecrypt(long duration) {
        decryptCounter.increment();
        decryptTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录KMS调用
     *
     * @param duration 耗时（毫秒）
     */
    public void recordKmsCall(long duration) {
        kmsCallCounter.increment();
        kmsCallTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录错误
     */
    public void recordError() {
        errorCounter.increment();
    }

    /**
     * 记录派生操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordProvisioningDerive(long duration) {
        provisioningDeriveCounter.increment();
        provisioningDeriveTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录封装操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordProvisioningWrap(long duration) {
        provisioningWrapCounter.increment();
        provisioningWrapTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录解封操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordProvisioningUnwrap(long duration) {
        provisioningUnwrapCounter.increment();
        provisioningUnwrapTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录数据密钥下发操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordKeyprovIssue(long duration) {
        keyprovIssueCounter.increment();
        keyprovIssueTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录SESSION模式加密操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordSessionEncrypt(long duration) {
        sessionEncryptCounter.increment();
        sessionEncryptTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录SESSION模式解密操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordSessionDecrypt(long duration) {
        sessionDecryptCounter.increment();
        sessionDecryptTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录非对称签名操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordSigningSign(long duration) {
        signingSignCounter.increment();
        signingSignTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录非对称验签操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordSigningVerify(long duration) {
        signingVerifyCounter.increment();
        signingVerifyTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录证书加密操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordCertencEncrypt(long duration) {
        certencEncryptCounter.increment();
        certencEncryptTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录密钥封装操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordCertencWrapKey(long duration) {
        certencWrapKeyCounter.increment();
        certencWrapKeyTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录证书申请提交操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordCertificateEnrollment(long duration) {
        certificateEnrollmentCounter.increment();
        certificateEnrollmentTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录证书申请查询操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordCertificateEnrollmentQuery(long duration) {
        certificateEnrollmentQueryCounter.increment();
        certificateEnrollmentQueryTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录 provider 维度证书申请提交（FW-SEC-DSN-CR-008 §8）。
     * provider 标签仅使用固定枚举（step-ca / legacy-rest），禁止高基数标签。
     */
    public void recordEnrollmentSubmit(String provider) {
        String normalized = normalizeProvider(provider);
        meterRegistry.counter("crypto.enrollment.submit.count", "provider", normalized).increment();
    }

    /**
     * 记录业务密钥材料创建（FW-SEC-DSN-CR-009）。
     *
     * @param duration 耗时（毫秒）
     */
    public void recordBusinessKeyCreate(long duration) {
        businessKeyCreateCounter.increment();
        businessKeyCreateTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录业务密钥封装（FW-SEC-DSN-CR-009）。
     *
     * @param duration 耗时（毫秒）
     */
    public void recordBusinessKeyWrap(long duration) {
        businessKeyWrapCounter.increment();
        businessKeyWrapTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录业务密钥元数据查询（FW-SEC-DSN-CR-009）。
     *
     * @param duration 耗时（毫秒）
     */
    public void recordBusinessKeyMetadata(long duration) {
        businessKeyMetadataCounter.increment();
        businessKeyMetadataTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录业务密钥吊销（FW-SEC-DSN-CR-009）。
     *
     * @param duration 耗时（毫秒）
     */
    public void recordBusinessKeyRevoke(long duration) {
        businessKeyRevokeCounter.increment();
        businessKeyRevokeTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录业务密钥目录解析（FW-SEC-DSN-CR-009）。
     *
     * @param duration 耗时（毫秒）
     */
    public void recordBusinessKeyDirectory(long duration) {
        businessKeyDirectoryCounter.increment();
        businessKeyDirectoryTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录导入证明验签成功（FW-SEC-DSN-CR-016 §8）。
     *
     * @param duration 耗时（毫秒）
     */
    public void recordImportProofVerify(long duration) {
        importProofVerifyCounter.increment();
        importProofVerifyTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录导入证明确定性拒绝（FW-SEC-DSN-CR-016 §8）。
     * <p>
     * reason 仅使用固定枚举（reject reason / certificate-evidence-rejected），
     * 禁止 importProof/proofInput/证书序列号/摘要等高基数或敏感标签。
     *
     * @param reason 拒绝类别
     */
    public void recordImportProofRejection(String reason) {
        meterRegistry.counter("crypto.import-proof.rejected.count",
                "reason", normalizeImportProofRejectReason(reason)).increment();
    }

    /**
     * 记录导入证明验签依赖/证书材料暂不可用（FW-SEC-DSN-CR-016 §7/§8，可重试语义）。
     */
    public void recordImportProofDependencyUnavailable() {
        importProofDependencyUnavailableCounter.increment();
    }

    /**
     * 记录业务密钥 Provider 请求（FW-SEC-DSN-CR-011 §8.3）。
     * <p>
     * 标签仅使用固定枚举（operation/result），禁止 keyId/idempotencyKey/operationId/证书序列号/
     * fingerprint/endpoint/Wrapped Key 等高基数或敏感标签。
     */
    public void recordBusinessKeyProviderRequest(String operation, String result) {
        meterRegistry.counter("crypto.kms.business-key.requests",
                "operation", normalizeBusinessKeyOperation(operation),
                "result", normalizeBusinessKeyResult(result)).increment();
    }

    /**
     * 记录业务密钥 Provider 调用时延（FW-SEC-DSN-CR-011 §8.3）。
     *
     * @param duration 耗时（毫秒）
     */
    public void recordBusinessKeyProviderLatency(String operation, long duration) {
        Timer.builder("crypto.kms.business-key.latency")
                .description("业务密钥 Provider 调用时延")
                .tag("operation", normalizeBusinessKeyOperation(operation))
                .register(meterRegistry)
                .record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录业务密钥 Provider 幂等结果（FW-SEC-DSN-CR-011 §8.3）。
     * <p>
     * {@code result} 仅使用固定枚举：accepted / conflict / unknown。
     */
    public void recordBusinessKeyProviderIdempotency(String result) {
        meterRegistry.counter("crypto.kms.business-key.idempotency",
                "result", normalizeIdempotencyResult(result)).increment();
    }

    /**
     * 记录业务密钥 Provider 结果未知（FW-SEC-DSN-CR-011 §8.3）。
     */
    public void recordBusinessKeyProviderOutcomeUnknown() {
        meterRegistry.counter("crypto.kms.business-key.outcome-unknown").increment();
    }

    /**
     * 注册业务密钥 Provider 就绪 gauge（1=READY，0=DOWN）。
     *
     * @param value 0/1 取值提供者
     */
    public void registerBusinessKeyProviderReadyGauge(java.util.function.Supplier<Number> value) {
        io.micrometer.core.instrument.Gauge
                .builder("crypto.kms.business-key.provider-ready", value, v -> v.get().doubleValue())
                .description("业务密钥 Provider 就绪（1=READY，0=DOWN）")
                .register(meterRegistry);
    }

    /**
     * 记录证书解析结果与来源（FW-SEC-DSN-CR-012 §11）。
     * <p>
     * source 仅使用固定枚举（inline-der / inline-spki / enrollment-store / provider-query /
     * domain-directory），禁止高基数或敏感标签。
     *
     * @param source   证据来源
     * @param duration 耗时（毫秒）
     */
    public void recordCertificateResolution(String source, long duration) {
        String normalized = normalizeEvidenceSource(source);
        meterRegistry.counter("crypto.cert-resolution.count", "source", normalized).increment();
        Timer.builder("crypto.cert-resolution.latency")
                .description("证书解析时延")
                .tag("source", normalized)
                .register(meterRegistry)
                .record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录证书解析失败（reason 仅使用固定枚举）。
     */
    public void recordCertificateResolutionFailure(String reason) {
        meterRegistry.counter("crypto.cert-resolution.failure.count",
                "reason", normalizeCertificateResolutionReason(reason)).increment();
    }

    /**
     * 记录 provider × outcome 维度证书申请结果（FW-SEC-DSN-CR-008 §8）。
     * outcome 仅使用固定枚举（issued/rejected/failed/unknown/pending）。
     */
    public void recordEnrollmentOutcome(String provider, String outcome) {
        String normalized = normalizeProvider(provider);
        String normalizedOutcome = normalizeOutcome(outcome);
        meterRegistry.counter("crypto.enrollment.outcome.count",
                "provider", normalized, "outcome", normalizedOutcome).increment();
    }

    private static String normalizeEvidenceSource(String source) {
        if (source == null) {
            return "unknown";
        }
        return switch (source.trim().toLowerCase()) {
            case "inline_der" -> "inline-der";
            case "inline_spki" -> "inline-spki";
            case "enrollment_store" -> "enrollment-store";
            case "provider_query" -> "provider-query";
            case "domain_directory" -> "domain-directory";
            default -> "unknown";
        };
    }

    private static String normalizeCertificateResolutionReason(String reason) {
        if (reason == null) {
            return "unknown";
        }
        return switch (reason.trim().toLowerCase()) {
            case "material_unavailable", "certificate_material_unavailable" -> "material-unavailable";
            case "evidence_mismatch", "certificate_evidence_mismatch" -> "evidence-mismatch";
            case "reference_ambiguous", "certificate_reference_ambiguous" -> "reference-ambiguous";
            case "dependency_unavailable", "crypto_dependency_unavailable" -> "dependency-unavailable";
            default -> "unknown";
        };
    }

    private static String normalizeImportProofRejectReason(String reason) {
        if (reason == null) {
            return "unknown";
        }
        return switch (reason.trim().toLowerCase()) {
            case "algorithm_not_allowed" -> "algorithm-not-allowed";
            case "invalid_length" -> "invalid-length";
            case "invalid_scalar" -> "invalid-scalar";
            case "high_s" -> "high-s";
            case "certificate_digest_mismatch" -> "certificate-digest-mismatch";
            case "signature_invalid" -> "signature-invalid";
            case "context_invalid" -> "context-invalid";
            case "certificate_evidence_rejected", "certificateevidencerejectedexception" ->
                    "certificate-evidence-rejected";
            default -> "unknown";
        };
    }

    private static String normalizeBusinessKeyOperation(String operation) {
        if (operation == null) {
            return "unknown";
        }
        return switch (operation.trim().toLowerCase()) {
            case "create" -> "create";
            case "wrap" -> "wrap";
            case "metadata" -> "metadata";
            case "revoke" -> "revoke";
            case "reconcile", "operation" -> "reconcile";
            case "capabilities", "capability" -> "capabilities";
            default -> "unknown";
        };
    }

    private static String normalizeBusinessKeyResult(String result) {
        if (result == null) {
            return "unknown";
        }
        return switch (result.trim().toLowerCase()) {
            case "success", "ok" -> "success";
            case "error", "failed", "failure" -> "error";
            case "conflict" -> "conflict";
            case "outcome-unknown", "outcome_unknown", "unknown" -> "outcome-unknown";
            default -> "unknown";
        };
    }

    private static String normalizeIdempotencyResult(String result) {
        if (result == null) {
            return "unknown";
        }
        return switch (result.trim().toLowerCase()) {
            case "accepted", "replay", "success" -> "accepted";
            case "conflict" -> "conflict";
            default -> "unknown";
        };
    }

    private static String normalizeProvider(String provider) {
        if (provider == null) {
            return "unknown";
        }
        String p = provider.trim().toLowerCase();
        return switch (p) {
            case "step-ca" -> "step-ca";
            case "legacy-rest", "legacy" -> "legacy-rest";
            default -> "unknown";
        };
    }

    private static String normalizeOutcome(String outcome) {
        if (outcome == null) {
            return "unknown";
        }
        String o = outcome.trim().toLowerCase();
        return switch (o) {
            case "issued" -> "issued";
            case "rejected" -> "rejected";
            case "failed" -> "failed";
            case "unknown" -> "unknown";
            case "pending", "submitting" -> "pending";
            default -> "unknown";
        };
    }
}
