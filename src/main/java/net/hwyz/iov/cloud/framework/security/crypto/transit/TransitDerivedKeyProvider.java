package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedEnvelopeViewFactory;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyEnvelopeCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeView;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.provider.CertificatePublicKeyWrapper;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCapability;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCommand;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyContextEncoder;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyKcv;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicy;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyProvider;
import net.hwyz.iov.cloud.framework.security.crypto.provider.ValidatedRecipientEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.provider.WrapEnvelopeContext;

import java.time.Clock;
import java.util.Arrays;
import java.util.Objects;

/**
 * FW-SEC 内置 TransitDerivedKeyProvider（FW-SEC-DSN-CR-019 §5.3）。
 * <p>
 * 在 FW-SEC 受控调用作用域内依次完成：
 * <ol>
 *   <li>策略注册表校验（rootRef/标签/purpose/派生版本/WrapMode，请求不得覆盖根名或算法）；</li>
 *   <li>收方最终密码学门禁（证据存在且未过期、SPKI/指纹非空、套件与 SPKI 算法一致）；</li>
 *   <li>编码受治理派生上下文并调用 Transit HMAC（严格解析 {@code vault:v1:<base64>}）；</li>
 *   <li>长度校验（32 字节）后本地证书公钥封装（ECDH-ES/RSA-OAEP，复用 CR-014/015 canonical 信封）；</li>
 *   <li>计算 KCV 与逻辑引用；</li>
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

    public TransitDerivedKeyProvider(DerivedKeyPolicyRegistry policyRegistry,
                                     DerivedKeyContextEncoder contextEncoder,
                                     TransitHmacClient transitHmacClient,
                                     CertificatePublicKeyWrapper wrapper,
                                     TransitRootMetadataCache rootMetadataCache,
                                     TransitDerivedKeyReadiness readiness,
                                     Clock clock) {
        this.policyRegistry = Objects.requireNonNull(policyRegistry, "policyRegistry must not be null");
        this.contextEncoder = Objects.requireNonNull(contextEncoder, "contextEncoder must not be null");
        this.transitHmacClient = Objects.requireNonNull(transitHmacClient, "transitHmacClient must not be null");
        this.wrapper = Objects.requireNonNull(wrapper, "wrapper must not be null");
        this.rootMetadataCache = Objects.requireNonNull(rootMetadataCache, "rootMetadataCache must not be null");
        this.readiness = Objects.requireNonNull(readiness, "readiness must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public DerivedWrappedKey deriveAndWrap(DerivedKeyCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        DerivedKeyPolicy policy = policyRegistry.validate(command);
        ValidatedRecipientEvidence recipient = finalGate(command.recipient(), policy);

        byte[] context = null;
        byte[] keyMaterial = null;
        try {
            context = contextEncoder.encode(policy, command.anchor(), command.purpose(),
                    policy.derivationVersion());
            TransitHmacResult hmac = transitHmacClient.hmac(
                    policy.transitKeyName(), policy.hmacAlgorithm(), context, command.operation());
            keyMaterial = hmac.hmac();
            if (keyMaterial == null || keyMaterial.length != DERIVED_KEY_LENGTH) {
                throw TransitException.derivedKeyLength(DERIVED_KEY_LENGTH,
                        keyMaterial == null ? 0 : keyMaterial.length);
            }

            long rootKeyVersion = rootMetadataCache.currentKeyVersion(policy.transitKeyName());
            String logicalKeyId = logicalKeyId(policy, command, rootKeyVersion);
            WrapEnvelopeContext envelopeContext = new WrapEnvelopeContext(
                    recipient.requestId(),
                    command.bizType().name(),
                    logicalKeyId,
                    command.context().businessKeyVersion(),
                    rootKeyVersion,
                    policy.derivationVersion(),
                    command.operation().operationId(),
                    command.purpose(),
                    recipient.sha256Fingerprint());

            DerivedWrappedKeyEnvelopeV1 envelope = wrapper.wrap(keyMaterial, recipient, envelopeContext);
            byte[] kcv = DerivedKeyKcv.first3Sha256(keyMaterial);
            byte[] envelopeBytes = DerivedKeyEnvelopeCanonical.envelopeBytesWithoutDigest(envelope);
            DerivedWrappedKeyEnvelopeView view = structuredView(envelope);

            return new DerivedWrappedKey(
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
        } finally {
            zeroize(context);
            zeroize(keyMaterial);
        }
    }

    @Override
    public DerivedKeyCapability capability() {
        return readiness.capability();
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
     * ECDH-ES v1 → 结构化只读视图（CR-015 §4.1）；RSA 无视图（旧格式读取路径）。
     */
    private static DerivedWrappedKeyEnvelopeView structuredView(DerivedWrappedKeyEnvelopeV1 envelope) {
        if (envelope.wrappingSuite() == null || !envelope.wrappingSuite().isEcdh()) {
            return null;
        }
        try {
            return DerivedEnvelopeViewFactory.toEcdhEsP256View(envelope);
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
