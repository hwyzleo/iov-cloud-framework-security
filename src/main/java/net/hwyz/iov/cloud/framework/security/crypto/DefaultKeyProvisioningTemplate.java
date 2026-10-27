package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateEvidenceRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.KeyMaterialModelMismatchException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceCertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.ProvisioningResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.ValidatedTboxDeviceCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCommand;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyProviderRouter;
import net.hwyz.iov.cloud.framework.security.crypto.provider.KmsDerivedKeyProvider;
import net.hwyz.iov.cloud.framework.security.crypto.provider.ValidatedRecipientEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * KeyProvisioningTemplate 默认实现（FW-SEC-DSN-CR-013 §4.4/§7.2/§8；FW-SEC-DSN-CR-019）。
 * <p>
 * 主入口 {@link #deriveAndWrap}：根派生型（{@code materialModel == DERIVED_ROOT}）经
 * <strong>两级校验</strong>（FW-SEC-DSN-CR-019）：
 * <ol>
 *   <li><strong>门面层</strong>：完整校验——证书解析、链验证、有效期、吊销状态、KU/EKU、
 *       Profile、主体绑定、指纹与套件推导，产出不可变 {@link ValidatedRecipientEvidence}；</li>
 *   <li><strong>Provider 层</strong>：只执行最终密码学门禁（存在且未过期、SPKI/指纹非空、
 *       套件与 SPKI 算法一致），随后 Transit 派生 + 本地证书公钥封装。</li>
 * </ol>
 * 门面层不再直接调用 {@code KmsClient.deriveAndWrap}，而是把命令交给
 * {@link DerivedKeyProviderRouter}（启动静态选择，禁运行时动态回退）；legacy 兼容路径
 * （{@code openbao-business-key}）由 {@link KmsDerivedKeyProvider} 保持与迁移前字节级一致。
 * <p>
 * 兼容门面 {@code deriveByVin/deriveByUid/wrapByVin/wrapByUid/wrapFor} 缺少派生所需的
 * purpose/operationId/幂等键，一律 fail-closed；{@code unwrapByVin/unwrapByUid} 仅在受控 legacy
 * 对称 KEK 场景（{@code crypto.provisioning.legacy-facade.enabled=true}）下保留旧行为。
 */
public class DefaultKeyProvisioningTemplate implements KeyProvisioningTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultKeyProvisioningTemplate.class);

    /** 根派生引用前缀（Provider 侧按 bizType 策略映射受治理根，仅作不透明引用/元数据） */
    private static final String ROOT_REF_PREFIX = "openbao-transit://transit/keys/";
    private static final String DEV_KEY_PREFIX = "dev-";

    private final KmsClient kmsClient;
    private final CryptoMetrics cryptoMetrics;
    private final CryptoProperties properties;
    private final DeviceResolver deviceResolver;
    private final CertResolver certResolver;
    private final CertificateEvidenceValidator evidenceValidator;
    private final TboxDeviceCertificateValidator tboxCertificateValidator;
    private final DerivedKeyProviderRouter providerRouter;
    private final boolean legacyFacadeEnabled;
    private final Clock clock;

    /**
     * 兼容构造：不携带 router 时按 legacy {@code openbao-business-key} 路由（保持既有行为）。
     */
    public DefaultKeyProvisioningTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics,
                                          CryptoProperties properties, DeviceResolver deviceResolver,
                                          CertResolver certResolver,
                                          CertificateEvidenceValidator evidenceValidator) {
        this(kmsClient, cryptoMetrics, properties, deviceResolver, certResolver, evidenceValidator, null, null);
    }

    /**
     * 兼容构造：携带 TBOX 证书 Profile 验证器（FW-SEC-DSN-CR-017），legacy 路由。
     */
    public DefaultKeyProvisioningTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics,
                                          CryptoProperties properties, DeviceResolver deviceResolver,
                                          CertResolver certResolver,
                                          CertificateEvidenceValidator evidenceValidator,
                                          TboxDeviceCertificateValidator tboxCertificateValidator) {
        this(kmsClient, cryptoMetrics, properties, deviceResolver, certResolver, evidenceValidator,
                tboxCertificateValidator, null);
    }

    /**
     * 完整构造：携带 Provider 路由器（FW-SEC-DSN-CR-019 §4）。
     *
     * @param providerRouter Provider 路由器；为 null 时按 legacy 兼容路由（迁移默认）
     */
    public DefaultKeyProvisioningTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics,
                                          CryptoProperties properties, DeviceResolver deviceResolver,
                                          CertResolver certResolver,
                                          CertificateEvidenceValidator evidenceValidator,
                                          TboxDeviceCertificateValidator tboxCertificateValidator,
                                          DerivedKeyProviderRouter providerRouter) {
        this.kmsClient = Objects.requireNonNull(kmsClient, "kmsClient must not be null");
        this.cryptoMetrics = cryptoMetrics;
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.deviceResolver = deviceResolver;
        this.certResolver = certResolver;
        this.evidenceValidator = evidenceValidator;
        this.tboxCertificateValidator = tboxCertificateValidator;
        this.providerRouter = providerRouter != null ? providerRouter
                : new DerivedKeyProviderRouter(DerivedKeyProviderRouter.LEGACY_PROVIDER, null,
                        new KmsDerivedKeyProvider(kmsClient));
        this.legacyFacadeEnabled = properties.getProvisioning().isLegacyFacadeEnabled();
        this.clock = Clock.systemUTC();
    }

    // ==================== 根派生 + 受控封装（主入口） ====================

    @Override
    public DerivedWrappedKey deriveAndWrap(BizType bizType, KeyAnchor anchor, KeyPurpose purpose,
                                           RecipientRef recipient, DerivationContext context,
                                           String operationId, String idempotencyKey,
                                           String protocolRequestId, String protocolBusinessDomain) {
        requireDerivedRoot(bizType);
        Objects.requireNonNull(anchor, "anchor must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        Objects.requireNonNull(recipient, "recipient must not be null（无隐式收方推断）");
        Objects.requireNonNull(context, "context must not be null");
        requireNonBlank(operationId, "operationId");
        requireNonBlank(idempotencyKey, "idempotencyKey");
        requireNonBlank(protocolRequestId, "protocolRequestId");
        requireNonBlank(protocolBusinessDomain, "protocolBusinessDomain");
        validateAnchorLevel(bizType, anchor);

        // 门面层完整证书校验 → 不可变已验证收方证据
        ValidatedRecipientEvidence validated = resolveValidatedRecipient(recipient);
        DerivedKeyCommand command = new DerivedKeyCommand(
                bizType, anchor, purpose, validated, context,
                new OperationContext(operationId, idempotencyKey),
                protocolRequestId, protocolBusinessDomain);

        long startTime = System.currentTimeMillis();
        try {
            DerivedWrappedKey result = providerRouter.deriveAndWrap(command);
            long duration = System.currentTimeMillis() - startTime;
            // anchor.toString() 仅含摘要，绝不含锚原文；不回显 Wrapped Key 与 KCV
            log.info("根派生封装成功: bizType={}, purpose={}, anchor={}, derivationVersion={}, "
                            + "wrappingSuite={}, businessKeyVersion={}, provider={}, duration={}ms",
                    bizType.name(), purpose, anchor, context.derivationVersion(),
                    validated.validatedWrapSuite(), context.businessKeyVersion(),
                    providerRouter.providerName(), duration);
            cryptoMetrics.recordProvisioningWrap(duration);
            return result;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("根派生封装失败: bizType={}, purpose={}, anchor={}, derivationVersion={}, "
                            + "wrappingSuite={}, provider={}",
                    bizType.name(), purpose, anchor, context.derivationVersion(),
                    validated.validatedWrapSuite(), providerRouter.providerName(), e);
            throw e;
        }
    }

    // ==================== 兼容门面（已废弃，fail-closed） ====================

    @Override
    @Deprecated
    public ProvisioningResult deriveByVin(String vin, BizType bizType) {
        throw legacyFacadeUnsupported("deriveByVin");
    }

    @Override
    @Deprecated
    public ProvisioningResult deriveByUid(String uid, BizType bizType) {
        throw legacyFacadeUnsupported("deriveByUid");
    }

    @Override
    @Deprecated
    public ProvisioningResult wrapByVin(String vin, BizType bizType) {
        throw legacyFacadeUnsupported("wrapByVin");
    }

    @Override
    @Deprecated
    public ProvisioningResult wrapByUid(String uid, BizType bizType) {
        throw legacyFacadeUnsupported("wrapByUid");
    }

    @Override
    @Deprecated
    public ProvisioningResult wrapFor(BizType keyBizType, String vinOrUid, String recipientUid) {
        throw legacyFacadeUnsupported("wrapFor");
    }

    @Override
    @Deprecated
    public byte[] unwrapByVin(String vin, BizType bizType, byte[] wrapped) {
        requireLegacyFacade("unwrapByVin");
        validateProvisionCapability(bizType);
        Objects.requireNonNull(vin, "vin must not be null");
        Objects.requireNonNull(wrapped, "wrapped must not be null");
        String normalizedVin = normalizeVin(vin);
        String deviceSn = resolveDeviceSn(normalizedVin, bizType);
        return doLegacyUnwrap(deviceSn, bizType, wrapped, "vin=" + normalizedVin);
    }

    @Override
    @Deprecated
    public byte[] unwrapByUid(String uid, BizType bizType, byte[] wrapped) {
        requireLegacyFacade("unwrapByUid");
        validateProvisionCapability(bizType);
        Objects.requireNonNull(uid, "uid must not be null");
        Objects.requireNonNull(wrapped, "wrapped must not be null");
        String normalizedUid = normalizeUid(uid);
        return doLegacyUnwrap(normalizedUid, bizType, wrapped, "uid=" + normalizedUid);
    }

    /**
     * 受控 legacy 对称 KEK 解封（仅 {@code legacy-facade.enabled=true} 时可达）。
     */
    private byte[] doLegacyUnwrap(String deviceSn, BizType bizType, byte[] wrapped, String logCtx) {
        String wrapKeyName = DEV_KEY_PREFIX + deviceSn;
        long startTime = System.currentTimeMillis();
        try {
            byte[] material = kmsClient.decryptWith(wrapKeyName, wrapped);
            long duration = System.currentTimeMillis() - startTime;
            log.info("legacy 解封成功: bizType={}, wrapKey={}, {} (sn={}), duration={}ms",
                    bizType.name(), wrapKeyName, logCtx, deviceSn, duration);
            cryptoMetrics.recordProvisioningUnwrap(duration);
            return material;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("legacy 解封失败: bizType={}, wrapKey={}, {}", bizType.name(), wrapKeyName, logCtx, e);
            throw e;
        }
    }

    // ==================== 门面层完整证书校验 → 已验证证据（FW-SEC-DSN-CR-019 两级校验） ====================

    /**
     * 门面层完整校验并产出不可变 {@link ValidatedRecipientEvidence}：
     * 解析/链/有效期/吊销/KU-EKU/Profile/主体绑定/指纹与套件推导；Provider 层不再重跑。
     */
    private ValidatedRecipientEvidence resolveValidatedRecipient(RecipientRef recipient) {
        if (recipient instanceof RecipientRef.DeviceCertificate c) {
            DeviceCertificateRef ref = new DeviceCertificateRef(c.certSerial(), c.requestId(),
                    c.certificateDer(), c.spki(), c.sha256Fingerprint(), null, c.context());
            // 统一 TBOX 设备证书 Profile 门禁（FW-SEC-DSN-CR-017 §7）：装配时单次解析 + 校验
            // （链/有效期/吊销 + Profile 语义），Provider/HSM 调用前强制，证书策略失败调用恒为 0。
            if (tboxCertificateValidator instanceof DefaultTboxDeviceCertificateValidator defaultValidator) {
                DefaultTboxDeviceCertificateValidator.ProfileValidation validation =
                        defaultValidator.validateWithEvidence(ref,
                                DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1);
                requireFullProfile(validation.validated());
                CertificateEvidence evidence = validation.evidence();
                String certSerial = c.certSerial() != null && !c.certSerial().isBlank()
                        ? c.certSerial() : evidence.serial();
                return toEvidence(certSerial, evidence, c.requestId(),
                        DeviceCertificateProfile.TBOX_DEVICE_ECDH_ES_P256_V1);
            }
            CertificateEvidence evidence = resolveDeviceCertificate(c);
            String certSerial = c.certSerial() != null && !c.certSerial().isBlank()
                    ? c.certSerial() : evidence.serial();
            return toEvidence(certSerial, evidence, c.requestId(), null);
        }
        if (recipient instanceof RecipientRef.PublicKey p) {
            // 直接公钥收方：无证书证据，不满足 DERIVED_ROOT 设备证书公钥封装门禁
            throw new CryptoException(CryptoException.Reason.UNSUPPORTED_RECIPIENT,
                    "deriveAndWrap 首期仅支持 DEVICE_CERT_PUBLIC_KEY 收方（需证书证据），"
                            + "PublicKey 收方不支持 DERIVED_ROOT: got=" + recipient.getClass().getSimpleName()) {};
        }
        throw new CryptoException(CryptoException.Reason.UNSUPPORTED_RECIPIENT,
                "deriveAndWrap 首期仅支持 DEVICE_CERT_PUBLIC_KEY 收方，got="
                        + recipient.getClass().getSimpleName()) {};
    }

    /**
     * 由证书证据组装不可变已验证收方证据（含有效期截止、套件推导与主体绑定摘要）。
     */
    private ValidatedRecipientEvidence toEvidence(String certSerial, CertificateEvidence evidence,
                                                  String requestId,
                                                  DeviceCertificateProfile profile) {
        if (evidence == null) {
            throw new CryptoDependencyUnavailableException(
                    "Resolved certificate evidence is null for derived key wrap");
        }
        byte[] leafDer = evidence.certificateDer() != null ? evidence.certificateDer() : evidence.spki();
        if (leafDer == null || leafDer.length == 0) {
            throw new CryptoDependencyUnavailableException(
                    "Resolved certificate evidence lacks DER/SPKI for derived key wrap");
        }
        if (evidence.spki() == null || evidence.spki().length == 0) {
            throw new CryptoDependencyUnavailableException(
                    "Resolved certificate evidence lacks SPKI for derived key wrap");
        }
        if (evidence.sha256Fingerprint() == null || evidence.sha256Fingerprint().isBlank()) {
            throw new CryptoDependencyUnavailableException(
                    "Resolved certificate evidence lacks SHA-256 fingerprint for derived key wrap");
        }
        WrappingSuite suite = suiteFor(evidence.spki());
        Instant now = clock.instant();
        Instant validUntil = extractNotAfter(leafDer, now);
        return new ValidatedRecipientEvidence(
                certSerial,
                leafDer,
                evidence.spki(),
                evidence.sha256Fingerprint(),
                profile,
                suite,
                now,
                validUntil,
                ValidatedRecipientEvidence.RecipientStatus.GOOD,
                subjectBindingDigest(certSerial, evidence.sha256Fingerprint()),
                requestId);
    }

    /**
     * 由叶子证书 DER 提取有效期截止；解析失败按证书证据不可用 fail-closed。
     */
    private static Instant extractNotAfter(byte[] leafDer, Instant fallback) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate x509 = (X509Certificate) factory.generateCertificate(
                    new java.io.ByteArrayInputStream(leafDer));
            return x509.getNotAfter().toInstant();
        } catch (Exception e) {
            // 已由门面解析的合法证书 DER 不应解析失败；失败按不可用处理
            return fallback;
        }
    }

    /**
     * 主体绑定摘要（非敏感）：SHA-256(serial + "|" + fingerprint) 十六进制小写；
     * 用于幂等冲突检测（相同幂等键不同证书/主体时拒绝，FW-SEC-DSN-CR-019 §11）。
     */
    private static String subjectBindingDigest(String certSerial, String fingerprint) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((Objects.toString(certSerial, "") + "|"
                            + Objects.toString(fingerprint, "")).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable for subject binding digest", e);
        }
    }

    /**
     * 完整 Keyprov 证书能力要求：P-256 + digitalSignature + keyAgreement + clientAuth
     * 全部成立（FW-SEC-DSN-CR-017 RD-017-4/§9）。统一 Profile 已强制双 KU，此处显式再校验。
     */
    private void requireFullProfile(ValidatedTboxDeviceCertificate validated) {
        if (!validated.p256() || !validated.digitalSignature()
                || !validated.keyAgreement() || !validated.clientAuth()) {
            throw new net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectedException(
                    net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileRejectReason.PROFILE_NOT_ALLOWED,
                    "TBOX device certificate profile capability incomplete: p256=" + validated.p256()
                            + ", digitalSignature=" + validated.digitalSignature()
                            + ", keyAgreement=" + validated.keyAgreement()
                            + ", clientAuth=" + validated.clientAuth());
        }
    }

    /**
     * 由收方公钥算法推导封装套件（EC→ECDH-ES / RSA→RSA-OAEP）；不支持时 fail-closed
     * （不可重试策略拒绝，FW-SEC-DSN-CR-014 §7.1）。
     */
    private WrappingSuite suiteFor(byte[] spki) {
        if (spki == null || spki.length == 0) {
            throw new CryptoDependencyUnavailableException(
                    "Resolved recipient SPKI is empty; cannot derive wrapping suite");
        }
        String keyAlgorithm;
        try {
            keyAlgorithm = CertificateEvidenceValidator.publicKeyAlgorithm(spki);
        } catch (RuntimeException e) {
            throw new CertificateEvidenceRejectedException(
                    CertificateEvidenceRejectedException.Reason.UNSUPPORTED_RECIPIENT_KEY,
                    "Unsupported or malformed recipient public key SPKI for keyprov wrap", e);
        }
        WrappingSuite suite = WrappingSuite.forRecipientKeyAlgorithm(keyAlgorithm);
        if (suite == null) {
            throw new CertificateEvidenceRejectedException(
                    CertificateEvidenceRejectedException.Reason.UNSUPPORTED_RECIPIENT_KEY,
                    "No keyprov wrapping suite for recipient key algorithm: " + keyAlgorithm);
        }
        return suite;
    }

    /**
     * 经门面统一证书解析（FW-SEC-DSN-CR-012）：按证据优先级取得并校验受信证书 DER/SPKI/指纹，
     * 任一环节缺失、冲突或状态不可用一律 fail-closed，不使用不可信输入。
     */
    private CertificateEvidence resolveDeviceCertificate(RecipientRef.DeviceCertificate c) {
        if (certResolver == null) {
            throw new CryptoDependencyUnavailableException(
                    "CertResolver not configured; cannot resolve TBOX certificate for derived key wrap");
        }
        DeviceCertificateRef ref = new DeviceCertificateRef(c.certSerial(), c.requestId(),
                c.certificateDer(), c.spki(), c.sha256Fingerprint(), null, c.context());
        CertificateResolvePolicy policy = businessKeyWrapPolicy();
        CertificateEvidence evidence = certResolver.resolve(ref, policy);
        if (evidenceValidator != null) {
            evidence = evidenceValidator.validate(evidence, ref, policy);
        }
        if (!evidence.hasLeafDer() && !evidence.hasSpki()) {
            throw new CryptoDependencyUnavailableException(
                    "Resolved certificate evidence lacks DER/SPKI for derived key wrap");
        }
        return evidence;
    }

    private CertificateResolvePolicy businessKeyWrapPolicy() {
        CryptoProperties.Pki.BusinessKeyWrap config = properties.getPki()
                .getCertificateResolution().getBusinessKeyWrap();
        return CertificateResolvePolicy.businessKeyWrap(config.isRequireCertificate(),
                config.isRequireTrustedChain(), config.isRequireGoodStatus());
    }

    // ==================== 治理校验 ====================

    private void requireDerivedRoot(BizType bizType) {
        Objects.requireNonNull(bizType, "bizType must not be null");
        if (!bizType.supportsDerivedRoot()) {
            throw new KeyMaterialModelMismatchException(
                    "deriveAndWrap 要求 prov != null && materialModel == DERIVED_ROOT，got bizType="
                            + bizType.name() + ", materialModel=" + bizType.materialModel()
                            + "（FW-SEC-DSN-CR-013 §7.3）");
        }
    }

    /**
     * 锚类型须与 {@code bizType.prov.anchor} 一致（VEHICLE→VIN；DEVICE→UID/device_sn），否则 fail-closed，
     * 避免同芯片因未解析 VIN 而派生出不同秘密。
     */
    private void validateAnchorLevel(BizType bizType, KeyAnchor anchor) {
        BizType.Anchor level = bizType.prov().anchor();
        boolean matches = (level == BizType.Anchor.VEHICLE && anchor.type() == KeyAnchor.AnchorType.VIN)
                || (level == BizType.Anchor.DEVICE && anchor.type() == KeyAnchor.AnchorType.UID);
        if (!matches) {
            throw new CryptoException(CryptoException.Reason.INVALID_KEY_ANCHOR,
                    "anchor type " + anchor.type() + " 与 bizType anchor level " + level
                            + " 不一致: bizType=" + bizType.name()) {};
        }
    }

    private void requireNonBlank(String value, String field) {
        Objects.requireNonNull(value, field + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }

    private void requireLegacyFacade(String method) {
        if (!legacyFacadeEnabled) {
            throw new CryptoException(CryptoException.Reason.LEGACY_FACADE_UNSUPPORTED,
                    method + " 默认 fail-closed：仅在受控 legacy 对称 KEK 场景下，"
                            + "显式开启 crypto.provisioning.legacy-facade.enabled=true 才可用"
                            + "（FW-SEC-DSN-CR-013 §12）") {};
        }
    }

    private CryptoException legacyFacadeUnsupported(String method) {
        return new CryptoException(CryptoException.Reason.LEGACY_FACADE_UNSUPPORTED,
                method + " 由 deriveAndWrap 取代并 fail-closed：缺少 purpose/operationId/幂等键，"
                        + "不得使用隐式默认 purpose 或随机幂等键（FW-SEC-DSN-CR-013 §4.4/§12）") {};
    }

    /**
     * 校验 bizType 支持派生/封装（prov != null），否则 fail-closed（legacy 解封沿用旧口径）。
     */
    private void validateProvisionCapability(BizType bizType) {
        Objects.requireNonNull(bizType, "bizType must not be null");
        if (!bizType.supportsProvision()) {
            throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                    "Non-PROVISION bizType cannot be used for provisioning: " + bizType.name()) {};
        }
    }

    /**
     * 解析 VIN→device_sn（经 DeviceResolver / VMD·TSP），仅 legacy 解封使用。
     */
    private String resolveDeviceSn(String vin, BizType bizType) {
        if (deviceResolver == null) {
            throw new CryptoDependencyUnavailableException(
                    "DeviceResolver unavailable, *ByVin methods require VMD/TSP binding. vin=" + vin);
        }
        return deviceResolver.resolveDeviceSn(vin, bizType);
    }

    private String normalizeVin(String vin) {
        return vin.trim().toUpperCase();
    }

    private String normalizeUid(String uid) {
        return uid.trim();
    }
}
