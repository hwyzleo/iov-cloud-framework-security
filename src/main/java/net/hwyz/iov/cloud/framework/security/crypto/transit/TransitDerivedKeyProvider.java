package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedEnvelopeViewFactory;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyEnvelopeCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyRequestDigest;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.DerivedWrapIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitReason;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeView;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.provider.CertificatePublicKeyWrapper;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCapability;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCommand;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyContextEncoder;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyKcv;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicy;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyProvider;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedWrapResultRecord;
import net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoderRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.OperationResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.provider.ValidatedRecipientEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.provider.WrapEnvelopeContext;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * FW-SEC 内置 TransitDerivedKeyProvider（FW-SEC-DSN-CR-019 §5.3；FW-SEC-DSN-CR-020 §3/§4）。
 * <p>
 * 在 FW-SEC 受控调用作用域内依次完成：
 * <ol>
 *   <li>策略注册表校验（rootRef/标签/purpose/派生版本/WrapMode，请求不得覆盖根名或算法）；</li>
 *   <li>收方最终密码学门禁（证据存在且未过期、SPKI/指纹非空、套件与 SPKI 算法一致）；</li>
 *   <li>解析 AAD profile（新 V2C ECDH-ES 必须配置并已注册，未配置 fail-closed）；</li>
 *   <li>选定根版本并计算 CR-020 版幂等请求摘要；</li>
 *   <li>结果存储幂等重放（SUCCEEDED 原字节返回；摘要不同冲突；PROCESSING 结果未知）；</li>
 *   <li>编码受治理派生上下文并调用 Transit HMAC（严格解析 {@code vault:v1:<base64>}）；</li>
 *   <li>{@code EnvelopeAadEncoder} 加密前输出 canonical AAD（FW-SEC-DSN-CR-020 §3），
 *       长度校验 + 防御性复制后交本地证书公钥封装（ECDH-ES/RSA-OAEP）；</li>
 *   <li>计算 KCV 与逻辑引用，持久化 SUCCEEDED 结果记录；</li>
 *   <li>{@code finally} 尽力清零可控明文缓冲。</li>
 * </ol>
 * 派生明文只允许在当前线程同步方法作用域内短暂存在；<strong>禁止</strong>放入 record、
 * 异常、lambda 捕获、异步队列、缓存或可序列化对象。Token 只经认证组件内存流转。
 */
public class TransitDerivedKeyProvider implements DerivedKeyProvider {

    public static final String PROVIDER_NAME = "openbao-transit-local-wrap";
    private static final int DERIVED_KEY_LENGTH = 32;
    private static final String KMS_KEY_REF_PREFIX = "openbao-transit://transit/keys/";

    private final DerivedKeyPolicyRegistry policyRegistry;
    private final DerivedKeyContextEncoder contextEncoder;
    private final TransitHmacClient transitHmacClient;
    private final CertificatePublicKeyWrapper wrapper;
    private final TransitRootMetadataCache rootMetadataCache;
    private final TransitDerivedKeyReadiness readiness;
    private final Clock clock;
    private final EnvelopeAadEncoderRegistry aadEncoderRegistry;
    private final OperationResultStore resultStore;
    private final String aadProfileId;
    private final Duration resultStoreTtl;

    /**
     * 兼容构造（legacy 模式，CR-020 §6）：不携带 AAD registry / 结果存储。
     * <p>
     * 新 V2C ECDH-ES 操作 fail-closed（无外部 AAD profile）；RSA-OAEP 与明确 legacy
     * consumer 走旧 core 路径且不提供字节级结果存储重放。
     */
    public TransitDerivedKeyProvider(DerivedKeyPolicyRegistry policyRegistry,
                                     DerivedKeyContextEncoder contextEncoder,
                                     TransitHmacClient transitHmacClient,
                                     CertificatePublicKeyWrapper wrapper,
                                     TransitRootMetadataCache rootMetadataCache,
                                     TransitDerivedKeyReadiness readiness,
                                     Clock clock) {
        this(policyRegistry, contextEncoder, transitHmacClient, wrapper, rootMetadataCache,
                readiness, clock, null, null, null, Duration.ofDays(30));
    }

    /**
     * 完整构造（CR-020）：携带受控 AAD registry 与结果存储。
     *
     * @param policyRegistry      策略注册表
     * @param contextEncoder      派生上下文编码器
     * @param transitHmacClient   Transit HMAC 客户端
     * @param wrapper             证书公钥封装器
     * @param rootMetadataCache   根元数据缓存
     * @param readiness           Transit 派生 readiness
     * @param clock               受控时钟
     * @param aadEncoderRegistry  AAD encoder 受控注册表（可为 null = legacy 模式）
     * @param resultStore         Operation 结果存储（可为 null = legacy 模式，无字节级重放）
     * @param aadProfileId        启动冻结的 AAD profile 标识（null/空 = 未配置，V2C 新操作 fail-closed）
     * @param resultStoreTtl      结果记录 TTL
     */
    public TransitDerivedKeyProvider(DerivedKeyPolicyRegistry policyRegistry,
                                     DerivedKeyContextEncoder contextEncoder,
                                     TransitHmacClient transitHmacClient,
                                     CertificatePublicKeyWrapper wrapper,
                                     TransitRootMetadataCache rootMetadataCache,
                                     TransitDerivedKeyReadiness readiness,
                                     Clock clock,
                                     EnvelopeAadEncoderRegistry aadEncoderRegistry,
                                     OperationResultStore resultStore,
                                     String aadProfileId,
                                     Duration resultStoreTtl) {
        this.policyRegistry = Objects.requireNonNull(policyRegistry, "policyRegistry must not be null");
        this.contextEncoder = Objects.requireNonNull(contextEncoder, "contextEncoder must not be null");
        this.transitHmacClient = Objects.requireNonNull(transitHmacClient, "transitHmacClient must not be null");
        this.wrapper = Objects.requireNonNull(wrapper, "wrapper must not be null");
        this.rootMetadataCache = Objects.requireNonNull(rootMetadataCache, "rootMetadataCache must not be null");
        this.readiness = Objects.requireNonNull(readiness, "readiness must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
        this.aadEncoderRegistry = aadEncoderRegistry;
        this.resultStore = resultStore;
        if (aadProfileId != null && aadProfileId.isBlank()) {
            throw new IllegalArgumentException("aadProfileId must not be blank when present");
        }
        this.aadProfileId = aadProfileId;
        this.resultStoreTtl = resultStoreTtl == null || resultStoreTtl.isZero() || resultStoreTtl.isNegative()
                ? Duration.ofDays(30) : resultStoreTtl;
    }

    @Override
    public DerivedWrappedKey deriveAndWrap(DerivedKeyCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        DerivedKeyPolicy policy = policyRegistry.validate(command);
        ValidatedRecipientEvidence recipient = finalGate(command.recipient(), policy);

        // CR-020 §6 收紧：新 V2C ECDH-ES 必须配置外部 AAD profile（未配置 fail-closed）
        String profileId = resolveAadProfile(recipient);

        // 选定根版本（缓存 TTL 内不触发 Transit 网络调用）
        long rootKeyVersion = rootMetadataCache.currentKeyVersion(policy.transitKeyName());
        String logicalKeyId = logicalKeyId(policy, command, rootKeyVersion);
        byte[] recipientDigest = recipientCertificateDigest(recipient);

        // CR-020 §4：幂等请求摘要（结果存储/重放对账，绑定实际 profile）
        String requestDigestHex = DerivedKeyRequestDigest.requestDigestV2Hex(
                profileId,
                recipient.requestId(),
                command.bizType().name(),
                command.purpose(),
                logicalKeyId,
                command.context().businessKeyVersion(),
                rootKeyVersion,
                policy.derivationVersion(),
                recipient.validatedWrapSuite(),
                recipientDigest);

        // 结果存储幂等重放（CR-020 §4/§7 测试 5/6）：SUCCEEDED 原字节返回；
        // 重放不得再次调用 encoder/随机源/Transit。
        Optional<DerivedWrapResultRecord> existing = resultStore == null
                ? Optional.empty() : resultStore.find(command.operation().operationId());
        if (existing.isPresent()) {
            DerivedWrapResultRecord record = existing.get();
            if (!record.requestDigestHex().equals(requestDigestHex)) {
                throw new DerivedWrapIdempotencyConflictException(
                        "operationId=" + command.operation().operationId()
                                + " 已存在且请求摘要（profile/hash）变化，返回幂等冲突"
                                + "（FW-SEC-DSN-CR-020 §4）");
            }
            if (record.status() == DerivedWrapResultRecord.Status.SUCCEEDED) {
                logReplay(command, record);
                return rebuild(record);
            }
            if (record.status() == DerivedWrapResultRecord.Status.NEW
                    || record.status() == DerivedWrapResultRecord.Status.PROCESSING) {
                // PROCESSING 不允许新建第二次密码操作：结果未知，原 operationId 对账
                throw new CryptoOperationOutcomeUnknownException(
                        "operationId=" + command.operation().operationId()
                                + " 结果存储状态 " + record.status()
                                + "（不允许第二次密码操作，请以原 operationId 对账）",
                        null, command.operation().operationId());
            }
            // FAILED / OUTCOME_UNKNOWN：允许按原 operationId 重试（覆盖保存）
        }

        byte[] context = null;
        byte[] keyMaterial = null;
        try {
            // CR-020 §3：加密前构建 EnvelopeAadContext 并由受控 registry 解析 encoder
            byte[] canonicalAad = null;
            if (recipient.validatedWrapSuite() != null && recipient.validatedWrapSuite().isEcdh()) {
                EnvelopeAadContext aadContext = new EnvelopeAadContext(
                        net.hwyz.iov.cloud.framework.security.crypto.model
                                .EcdhEsP256EnvelopeViewV1.FORMAT_VERSION_V1,
                        recipient.validatedWrapSuite(),
                        recipient.requestId(),
                        command.bizType().name(),
                        command.purpose(),
                        logicalKeyId,
                        command.context().businessKeyVersion(),
                        rootKeyVersion,
                        policy.derivationVersion(),
                        recipientDigest);
                canonicalAad = encodeCanonicalAad(profileId, aadContext);
            }

            context = contextEncoder.encode(policy, command.anchor(), command.purpose(),
                    policy.derivationVersion());
            TransitHmacResult hmac = transitHmacClient.hmac(
                    policy.transitKeyName(), policy.hmacAlgorithm(), context, command.operation());
            keyMaterial = hmac.hmac();
            if (keyMaterial == null || keyMaterial.length != DERIVED_KEY_LENGTH) {
                throw TransitException.derivedKeyLength(DERIVED_KEY_LENGTH,
                        keyMaterial == null ? 0 : keyMaterial.length);
            }

            WrapEnvelopeContext envelopeContext = new WrapEnvelopeContext(
                    recipient.requestId(),
                    command.bizType().name(),
                    logicalKeyId,
                    command.context().businessKeyVersion(),
                    rootKeyVersion,
                    policy.derivationVersion(),
                    command.operation().operationId(),
                    command.purpose(),
                    recipient.sha256Fingerprint(),
                    profileId);

            DerivedWrappedKeyEnvelopeV1 envelope = canonicalAad != null
                    ? wrapper.wrapWithAad(keyMaterial, recipient, envelopeContext, canonicalAad)
                    : wrapper.wrap(keyMaterial, recipient, envelopeContext);
            byte[] kcv = DerivedKeyKcv.first3Sha256(keyMaterial);
            byte[] envelopeBytes = DerivedKeyEnvelopeCanonical.envelopeBytesWithoutDigest(envelope);
            DerivedWrappedKeyEnvelopeView view = structuredView(envelope, profileId);

            DerivedWrappedKey result = new DerivedWrappedKey(
                    logicalKeyId,
                    KMS_KEY_REF_PREFIX + policy.transitKeyName(),
                    rootKeyVersion,
                    policy.derivationVersion(),
                    envelope.wrappingSuite(),
                    view,
                    envelopeBytes,
                    envelope.envelopeDigest(),
                    kcv,
                    command.operation().operationId());

            // CR-020 §4：持久化 SUCCEEDED 记录（profileId/canonicalAad/aadDigest/ciphertext/tag/coreEnvelopeDigest）
            if (resultStore != null) {
                resultStore.save(toRecord(command, requestDigestHex, profileId, result, envelope));
            }
            return result;
        } finally {
            zeroize(context);
            zeroize(keyMaterial);
        }
    }

    @Override
    public DerivedKeyCapability capability() {
        return readiness.capability();
    }

    // ==================== AAD profile 解析（FW-SEC-DSN-CR-020 §2/§6） ====================

    /**
     * 解析 AAD profile：新 V2C ECDH-ES 必须配置且已注册；RSA-OAEP 无 AAD 概念（legacy consumer）。
     * 配置缺失/未注册一律 fail-closed，不得回退旧 FW AAD 或空 AAD。
     */
    private String resolveAadProfile(ValidatedRecipientEvidence recipient) {
        WrappingSuite suite = recipient.validatedWrapSuite();
        if (suite != null && suite.isEcdh()) {
            if (aadProfileId == null || aadProfileId.isBlank()) {
                throw new TransitException(TransitReason.AAD_PROFILE_NOT_CONFIGURED,
                        "新 V2C ECDH-ES keyprov 未配置 aadProfileId，不得为新的 V2C operation "
                                + "静默生成旧 core AAD 信封（FW-SEC-DSN-CR-020 §6）");
            }
            if (aadEncoderRegistry == null || !aadEncoderRegistry.has(aadProfileId)) {
                throw new TransitException(TransitReason.AAD_PROFILE_UNAVAILABLE,
                        "配置的 aadProfileId=" + aadProfileId + " 未注册（可用: "
                                + (aadEncoderRegistry == null ? "[]" : aadEncoderRegistry.profileIds())
                                + "），不得回退旧 FW AAD（FW-SEC-DSN-CR-020 §2）");
            }
            return aadProfileId;
        }
        // RSA-OAEP：无 AAD 概念；legacy consumer 路径
        return null;
    }

    /**
     * 加密前由受控 registry 解析 encoder 输出 canonical AAD：防御性复制 + 大小校验。
     * encoder 输出非确定/超限/抛错由 registry 与 wrapper 双层 fail-closed。
     */
    private byte[] encodeCanonicalAad(String profileId, EnvelopeAadContext aadContext) {
        byte[] encoded = aadEncoderRegistry.require(profileId).encode(aadContext);
        if (encoded == null || encoded.length == 0) {
            throw new TransitException(TransitReason.AAD_ENCODER_OUTPUT_INVALID,
                    "EnvelopeAadEncoder profileId=" + profileId + " 输出为空（FW-SEC-DSN-CR-020 §7 测试 3）");
        }
        if (encoded.length > net.hwyz.iov.cloud.framework.security.crypto.model
                .EcdhEsP256EnvelopeViewV1.MAX_CANONICAL_AAD_LENGTH) {
            throw new TransitException(TransitReason.AAD_ENCODER_OUTPUT_INVALID,
                    "EnvelopeAadEncoder profileId=" + profileId + " 输出超过 "
                            + net.hwyz.iov.cloud.framework.security.crypto.model
                            .EcdhEsP256EnvelopeViewV1.MAX_CANONICAL_AAD_LENGTH + " 字节上限");
        }
        return encoded.clone();
    }

    // ==================== 结果存储重建（CR-020 §4：重放读取原记录） ====================

    /**
     * SUCCEEDED 记录 → 原字节重放：重建 core 信封与结构化 view。
     * <strong>不得</strong>重新调用 encoder、随机源或 Transit（FW-SEC-DSN-CR-020 §7 测试 5/6）。
     */
    private DerivedWrappedKey rebuild(DerivedWrapResultRecord record) {
        WrappingSuite suite = WrappingSuite.fromWireName(record.wrappingSuiteWire());
        DerivedWrappedKeyEnvelopeV1 envelope = new DerivedWrappedKeyEnvelopeV1(
                DerivedWrappedKeyEnvelopeV1.V1,
                suite,
                record.serverEphemeralPublicKey(),
                record.hkdfSalt(),
                record.hkdfContextVersion(),
                record.nonce(),
                record.ciphertext(),
                record.authenticationTag(),
                record.canonicalAad(),
                record.aadDigest(),
                record.recipientCertificateFingerprint(),
                record.logicalKeyId(),
                record.purpose(),
                record.businessKeyVersion(),
                record.rootKeyVersion(),
                record.derivationVersion(),
                record.kcv(),
                record.envelopeOperationId(),
                record.envelopeDigest());
        DerivedWrappedKeyEnvelopeView view = structuredView(envelope, record.aadProfileId());
        return new DerivedWrappedKey(
                record.logicalKeyId(),
                record.kmsKeyRef(),
                record.rootKeyVersion(),
                record.derivationVersion(),
                suite,
                view,
                record.envelopeBytes(),
                record.envelopeDigest(),
                record.kcv(),
                record.operationId());
    }

    /**
     * 由成功结果构建 SUCCEEDED 持久化记录（CR-020 §4：profileId/canonicalAad/aadDigest/
     * ciphertext/tag/coreEnvelopeDigest 与完整信封重建参数；不含业务明文/KEK/shared secret）。
     */
    private DerivedWrapResultRecord toRecord(DerivedKeyCommand command, String requestDigestHex,
                                             String profileId, DerivedWrappedKey result,
                                             DerivedWrappedKeyEnvelopeV1 envelope) {
        Instant now = clock.instant();
        return new DerivedWrapResultRecord(
                command.operation().operationId(),
                requestDigestHex,
                profileId,
                DerivedWrapResultRecord.Status.SUCCEEDED,
                result.logicalKeyId(),
                result.kmsKeyRef(),
                result.rootKeyVersion(),
                result.derivationVersion(),
                result.wrappingSuite().wireName(),
                result.envelopeBytes(),
                result.envelopeDigest(),
                result.kcv(),
                envelope.serverEphemeralPublicKey(),
                envelope.hkdfSalt(),
                envelope.hkdfContextVersion(),
                envelope.nonce(),
                envelope.ciphertext(),
                envelope.authenticationTag(),
                envelope.aad(),
                envelope.aadDigest(),
                envelope.recipientCertificateFingerprint(),
                envelope.purpose(),
                envelope.businessKeyVersion(),
                envelope.operationId(),
                now,
                now.plus(resultStoreTtl),
                null);
    }

    private void logReplay(DerivedKeyCommand command, DerivedWrapResultRecord record) {
        // 非敏感重放日志：不含密文/AAD/KCV 原文
        org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TransitDerivedKeyProvider.class);
        log.info("结果存储重放（原字节返回）: operationId={}, aadProfileId={}, logicalKeyId={}, "
                        + "suite={}, status={}",
                command.operation().operationId(), record.aadProfileId(), record.logicalKeyId(),
                record.wrappingSuiteWire(), record.status());
    }

    // ==================== 收方最终密码学门禁 ====================

    /**
     * Provider 层最终门禁（FW-SEC-DSN-CR-019 §5.3/RD-019-4）：
     * 证据存在且未过期、leaf DER/SPKI/指纹一致且非空、WrapMode 允许、SPKI 算法/曲线与套件匹配。
     * 门面已完成全量证书校验，此处<strong>不</strong>重跑目录/OCSP/CRL/证书链。
     */
    private ValidatedRecipientEvidence finalGate(ValidatedRecipientEvidence recipient,
                                                 DerivedKeyPolicy policy) {
        if (recipient == null) {
            throw TransitException.recipientInvalid("validated recipient evidence is null");
        }
        if (recipient.validUntil() != null && clock.instant().isAfter(recipient.validUntil())) {
            throw TransitException.recipientInvalid(
                    "recipient certificate expired at " + recipient.validUntil());
        }
        if (recipient.spki() == null || recipient.spki().length == 0) {
            throw TransitException.recipientInvalid("recipient SPKI is empty");
        }
        if (recipient.leafCertificateDer() == null || recipient.leafCertificateDer().length == 0) {
            throw TransitException.recipientInvalid("recipient leaf certificate DER is empty");
        }
        if (recipient.sha256Fingerprint() == null || recipient.sha256Fingerprint().isBlank()) {
            throw TransitException.recipientInvalid("recipient certificate fingerprint is missing");
        }
        if (!policy.allowedWrapSuites().contains(recipient.validatedWrapSuite())) {
            throw TransitException.recipientInvalid(
                    "validatedWrapSuite=" + recipient.validatedWrapSuite()
                            + " 不在策略允许范围 " + policy.allowedWrapSuites());
        }
        if (!CertificatePublicKeyWrapper.recipientMatchesSuite(recipient.validatedWrapSuite(), recipient.spki())) {
            throw TransitException.recipientInvalid(
                    "validatedWrapSuite=" + recipient.validatedWrapSuite()
                            + " 与收方 SPKI 算法/曲线不一致（请求不得覆盖已验证套件）");
        }
        return recipient;
    }

    // ==================== 逻辑引用与视图 ====================

    /**
     * 逻辑派生实例标识：确定性、非敏感（只含锚摘要）；同逻辑输入（根版本/锚/purpose/派生版本）
     * 相同，换件/换证书不改变。
     */
    private static String logicalKeyId(DerivedKeyPolicy policy, DerivedKeyCommand command,
                                       long rootKeyVersion) {
        return "openiov|" + policy.bizType().name() + "|" + command.purpose().name()
                + "|" + policy.derivationVersion() + "|rootV" + rootKeyVersion
                + "|" + command.anchor().digest();
    }

    /**
     * 收方证书 SHA-256 摘要（32 字节）：由已验证指纹（小写十六进制）还原，供
     * EnvelopeAadContext 与 CR-020 幂等摘要使用。
     */
    private byte[] recipientCertificateDigest(ValidatedRecipientEvidence recipient) {
        byte[] digest = CanonicalEncoding.hexDecode(recipient.sha256Fingerprint());
        if (digest == null || digest.length != net.hwyz.iov.cloud.framework.security.crypto.model
                .EcdhEsP256EnvelopeViewV1.DIGEST_LENGTH) {
            throw TransitException.recipientInvalid(
                    "recipient certificate fingerprint must encode a 32-byte SHA-256 digest");
        }
        return digest;
    }

    /**
     * ECDH-ES v1 → 结构化只读视图（CR-015 §4.1；CR-020 §2：携带 aadProfileId）；
     * RSA 无视图（旧格式读取路径）。
     */
    private static DerivedWrappedKeyEnvelopeView structuredView(DerivedWrappedKeyEnvelopeV1 envelope,
                                                                String aadProfileId) {
        if (envelope.wrappingSuite() == null || !envelope.wrappingSuite().isEcdh()) {
            return null;
        }
        try {
            return DerivedEnvelopeViewFactory.toEcdhEsP256View(envelope, aadProfileId);
        } catch (RuntimeException e) {
            throw TransitException.formatInvalid(
                    "envelope cannot be projected to structured view v1: " + e.getMessage());
        }
    }

    private static void zeroize(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
