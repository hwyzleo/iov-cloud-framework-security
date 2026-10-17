package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.CertEnrollmentTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateChainValidator;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertificateEnrollmentResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.EnrollmentRecord;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateMaterialUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateReferenceAmbiguousException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * framework 默认生产级证书解析编排（FW-SEC-DSN-CR-012 §5/§6）。
 * <p>
 * 解析顺序固定为：inline DER → inline SPKI（policy 允许）→ requestId / 注册结果存储
 * → Provider serial query（capability 允许）→ 领域目录 locator（回到前两步取材料）。
 * <p>
 * 安全边界：framework 不拥有主体/serial 目录权威；多个目录 Adapter 命中不同 locator 时拒绝，
 * 不按 Bean 顺序取首个；任一路径缺材料 / 来源缺失 / 结果不唯一 / 证据冲突时 fail-closed。
 * 本类只负责「取到并规范化证据」，场景化校验由 {@link CertificateEvidenceValidator} 统一执行。
 */
public class DefaultCertResolver implements CertResolver {

    private static final Logger log = LoggerFactory.getLogger(DefaultCertResolver.class);

    private final ObjectProvider<CertificateEnrollmentResultStore> resultStoreProvider;
    private final ObjectProvider<CertEnrollmentTemplate> enrollmentTemplateProvider;
    private final ObjectProvider<PkiClient> pkiClientProvider;
    private final ObjectProvider<CertificateReferenceDirectory> directoryProvider;
    private final CertificateChainValidator chainValidator = new CertificateChainValidator();
    private final CryptoProperties properties;
    private final CryptoMetrics cryptoMetrics;

    public DefaultCertResolver(ObjectProvider<CertificateEnrollmentResultStore> resultStoreProvider,
                               ObjectProvider<CertEnrollmentTemplate> enrollmentTemplateProvider,
                               ObjectProvider<PkiClient> pkiClientProvider,
                               ObjectProvider<CertificateReferenceDirectory> directoryProvider,
                               CryptoProperties properties) {
        this(resultStoreProvider, enrollmentTemplateProvider, pkiClientProvider, directoryProvider,
                properties, null);
    }

    public DefaultCertResolver(ObjectProvider<CertificateEnrollmentResultStore> resultStoreProvider,
                               ObjectProvider<CertEnrollmentTemplate> enrollmentTemplateProvider,
                               ObjectProvider<PkiClient> pkiClientProvider,
                               ObjectProvider<CertificateReferenceDirectory> directoryProvider,
                               CryptoProperties properties,
                               CryptoMetrics cryptoMetrics) {
        this.resultStoreProvider = resultStoreProvider;
        this.enrollmentTemplateProvider = enrollmentTemplateProvider;
        this.pkiClientProvider = pkiClientProvider;
        this.directoryProvider = directoryProvider;
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
        this.cryptoMetrics = cryptoMetrics;
    }

    @Override
    public CertificateEvidence resolve(DeviceCertificateRef ref, CertificateResolvePolicy policy) {
        Objects.requireNonNull(ref, "ref must not be null");
        Objects.requireNonNull(policy, "policy must not be null");
        long start = System.currentTimeMillis();
        try {
            CertificateEvidence evidence = doResolve(ref, policy);
            if (cryptoMetrics != null) {
                cryptoMetrics.recordCertificateResolution(evidence.source().name(),
                        System.currentTimeMillis() - start);
            }
            return evidence;
        } catch (CertificateMaterialUnavailableException | CertificateReferenceAmbiguousException e) {
            if (cryptoMetrics != null) {
                cryptoMetrics.recordCertificateResolutionFailure(e.getReason().name());
            }
            throw e;
        }
    }

    private CertificateEvidence doResolve(DeviceCertificateRef ref, CertificateResolvePolicy policy) {
        CryptoProperties.Pki.CertificateResolution config = properties.getPki().getCertificateResolution();

        // 1. 调用方直接携带 leaf DER
        if (ref.hasInlineDer()) {
            Long start = System.currentTimeMillis();
            CertificateEvidence evidence = CertificateEvidenceValidator.fromCertificateDer(
                    ref.certificateDer(), EvidenceSource.INLINE_DER);
            log.debug("证书解析命中 inline DER: serial={}, fingerprint={}, duration={}ms",
                    evidence.serial(), evidence.sha256Fingerprint(), System.currentTimeMillis() - start);
            return evidence;
        }

        // 2. 调用方直接携带 SPKI（仅 policy 允许裸公钥）
        if (ref.hasInlineSpki() && policy.allowBareSpki()) {
            return CertificateEvidenceValidator.fromSpki(
                    ref.spki(), ref.sha256Fingerprint(), EvidenceSource.INLINE_SPKI);
        }

        // 3. requestId → 注册结果存储 / 注册门面
        if (ref.requestId() != null && !ref.requestId().isBlank()) {
            CertificateEvidence evidence = byRequestId(ref.requestId());
            if (evidence != null) {
                return evidence;
            }
        }

        // 4. Provider serial query（仅 capability/配置允许，如 legacy-rest）
        if (ref.certSerial() != null && !ref.certSerial().isBlank()
                && config.isProviderQueryEnabled() && providerSupportsSerialQuery()) {
            CertificateEvidence evidence = byProviderSerial(ref.certSerial());
            if (evidence != null) {
                return evidence;
            }
        }

        // 5. 领域目录 locator → 回到 3/4
        if (config.isDomainDirectoryEnabled()) {
            CertificateEvidence evidence = byDomainDirectory(ref, config);
            if (evidence != null) {
                return evidence;
            }
        }

        throw new CertificateMaterialUnavailableException(
                "No certificate evidence source could resolve the reference to an issued certificate"
                        + " (inline DER/SPKI, requestId, provider serial query, domain directory all unavailable)");
    }

    @Override
    public byte[] resolveByVin(String vin) {
        return resolve(DeviceCertificateRef.ofSubject(CertificateSubjectRef.ofVehicle(vin)),
                CertificateResolvePolicy.certEncryption()).certificateDer();
    }

    @Override
    public byte[] resolveByDeviceSn(String deviceSn) {
        return resolve(DeviceCertificateRef.ofSubject(CertificateSubjectRef.ofDevice(deviceSn)),
                CertificateResolvePolicy.certEncryption()).certificateDer();
    }

    @Override
    public byte[] resolveByUid(String uid) {
        return resolve(DeviceCertificateRef.ofSubject(CertificateSubjectRef.ofUser(uid)),
                CertificateResolvePolicy.certEncryption()).certificateDer();
    }

    @Override
    public byte[] resolveBySerial(String certSerial) {
        return resolve(DeviceCertificateRef.ofSerial(certSerial),
                CertificateResolvePolicy.certEncryption()).certificateDer();
    }

    // ==================== 来源 ====================

    private CertificateEvidence byRequestId(String requestId) {
        CertificateEnrollmentResultStore store = resultStoreProvider != null
                ? resultStoreProvider.getIfAvailable() : null;
        if (store != null) {
            EnrollmentRecord record = store.findByRequestId(requestId).orElse(null);
            if (record != null) {
                if (record.state() == EnrollmentState.ISSUED
                        && record.leafCertificate() != null && record.leafCertificate().length > 0) {
                    return CertificateEvidenceValidator.fromCertificateDer(
                            record.leafCertificate(), record.certificateChain(),
                            EvidenceSource.ENROLLMENT_STORE);
                }
                throw new CertificateMaterialUnavailableException(
                        "Enrollment request is not issued yet: requestId=" + requestId
                                + ", state=" + record.state());
            }
        }

        CertEnrollmentTemplate enrollment = enrollmentTemplateProvider != null
                ? enrollmentTemplateProvider.getIfAvailable() : null;
        if (enrollment != null) {
            try {
                IssuedCertificate certificate = enrollment.getCertificate(requestId);
                if (certificate != null && certificate.leafCertificate() != null) {
                    return CertificateEvidenceValidator.fromCertificateDer(
                            certificate.leafCertificate(), certificate.certificateChain(),
                            EvidenceSource.ENROLLMENT_STORE);
                }
            } catch (CertificateMaterialUnavailableException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new CertificateMaterialUnavailableException(
                        "Failed to read issued certificate for requestId=" + requestId + ": " + e.getMessage(), e);
            }
        }
        return null;
    }

    private CertificateEvidence byProviderSerial(String certSerial) {
        PkiClient pkiClient = pkiClientProvider != null ? pkiClientProvider.getIfAvailable() : null;
        if (pkiClient == null) {
            return null;
        }
        PkiClient.CertificateResponse response = pkiClient.queryCertificate(certSerial);
        if (response == null || response.leafCertificate() == null
                || response.leafCertificate().length == 0) {
            return null;
        }
        List<byte[]> chain = parseChain(response.certificateChain());
        return CertificateEvidenceValidator.fromCertificateDer(
                response.leafCertificate(), chain, EvidenceSource.PROVIDER_QUERY);
    }

    private CertificateEvidence byDomainDirectory(DeviceCertificateRef ref,
                                                   CryptoProperties.Pki.CertificateResolution config) {
        List<CertificateLocator> locators = locateAll(ref);
        if (locators.isEmpty()) {
            return null;
        }
        if (locators.size() > 1) {
            if (config.isRequireUniqueResult()) {
                throw new CertificateReferenceAmbiguousException(
                        "Multiple domain directories returned conflicting certificate locators: "
                                + locators);
            }
            log.warn("多个领域目录返回不同 locator，按配置 require-unique-result=false 取首个: {}", locators);
        }
        return follow(locators.get(0));
    }

    private List<CertificateLocator> locateAll(DeviceCertificateRef ref) {
        if (directoryProvider == null) {
            return List.of();
        }
        Set<CertificateLocator> locators = new LinkedHashSet<>();
        directoryProvider.orderedStream().forEach(directory -> {
            try {
                directory.locate(ref).ifPresent(locators::add);
            } catch (RuntimeException e) {
                throw new CertificateMaterialUnavailableException(
                        "Domain certificate directory failed: " + e.getMessage(), e);
            }
        });
        return new ArrayList<>(locators);
    }

    private CertificateEvidence follow(CertificateLocator locator) {
        if (locator instanceof CertificateLocator.EnrollmentRequest request) {
            CertificateEvidence evidence = byRequestId(request.requestId());
            if (evidence != null) {
                return new CertificateEvidence(evidence.certificateDer(), evidence.spki(),
                        evidence.serial(), evidence.sha256Fingerprint(), evidence.chain(),
                        EvidenceSource.DOMAIN_DIRECTORY);
            }
            throw new CertificateMaterialUnavailableException(
                    "Domain directory pointed to an enrollment request with no issued certificate: "
                            + request.requestId());
        }
        if (locator instanceof CertificateLocator.ProviderSerial providerSerial) {
            CertificateEvidence evidence = byProviderSerial(providerSerial.serial());
            if (evidence != null) {
                return new CertificateEvidence(evidence.certificateDer(), evidence.spki(),
                        evidence.serial(), evidence.sha256Fingerprint(), evidence.chain(),
                        EvidenceSource.DOMAIN_DIRECTORY);
            }
            throw new CertificateMaterialUnavailableException(
                    "Domain directory pointed to a provider serial with no resolvable certificate: "
                            + providerSerial.serial());
        }
        throw new CertificateMaterialUnavailableException("Unsupported certificate locator: " + locator);
    }

    private boolean providerSupportsSerialQuery() {
        String provider = properties.getPki().getProvider();
        if (provider == null || provider.isBlank()) {
            return true;
        }
        // step-ca 无通用按 serial 回查已签发证书的 CA 路由（FW-SEC-DSN-CR-008 §5.3）
        return !provider.equalsIgnoreCase("step-ca");
    }

    private List<byte[]> parseChain(byte[] certificateChain) {
        if (certificateChain == null || certificateChain.length == 0) {
            return List.of();
        }
        try {
            return chainValidator.parseCertificateChain(certificateChain);
        } catch (RuntimeException e) {
            throw new CertificateMaterialUnavailableException(
                    "Provider returned an unparseable certificate chain", e);
        }
    }
}
