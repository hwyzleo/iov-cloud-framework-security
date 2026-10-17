package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.cipher.EciesCipher;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.RsaOaepCipher;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopedData;
import net.hwyz.iov.cloud.framework.security.crypto.model.Recipient;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateSubjectRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * CertEncryptionTemplate 默认实现（CR-006）
 * <p>
 * 解析收方公钥 -> 判断密钥类型（EC / RSA）-> 分派到 {@link EciesCipher} / {@link RsaOaepCipher}。
 * <p>
 * 收方公钥来源：
 * <ul>
 *   <li>{@link Recipient.CertRecipient} -> 解析证书取公钥</li>
 *   <li>{@link Recipient.PublicKeyRecipient} -> 直接用 SPKI</li>
 *   <li>{@link Recipient.SubjectRecipient} -> 经 {@link CertResolver} 解析主体为证书，再取公钥</li>
 * </ul>
 * fail-closed：证书解析失败、算法不支持、参数非法一律抛 {@link CryptoException}。
 */
public class DefaultCertEncryptionTemplate implements CertEncryptionTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultCertEncryptionTemplate.class);

    private final EciesCipher eciesCipher;
    private final RsaOaepCipher rsaOaepCipher;
    private final CryptoMetrics cryptoMetrics;
    private final CertResolver certResolver;
    private final CertificateEvidenceValidator evidenceValidator;

    public DefaultCertEncryptionTemplate(CryptoMetrics cryptoMetrics, CertResolver certResolver) {
        this(cryptoMetrics, certResolver, null);
    }

    public DefaultCertEncryptionTemplate(CryptoMetrics cryptoMetrics, CertResolver certResolver,
                                         CertificateEvidenceValidator evidenceValidator) {
        this.eciesCipher = new EciesCipher();
        this.rsaOaepCipher = new RsaOaepCipher();
        this.cryptoMetrics = cryptoMetrics;
        this.certResolver = certResolver;
        this.evidenceValidator = evidenceValidator;
    }

    @Override
    public EnvelopedData encryptFor(Recipient recipient, byte[] plaintext) {
        Objects.requireNonNull(recipient, "recipient must not be null");
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        long startTime = System.currentTimeMillis();
        try {
            byte[] pubKeyDer = resolveRecipientPublicKey(recipient);
            String keyAlgo = detectKeyAlgorithm(pubKeyDer);

            EnvelopedData result;
            if ("EC".equals(keyAlgo)) {
                result = eciesCipher.encrypt(pubKeyDer, plaintext);
            } else if ("RSA".equals(keyAlgo)) {
                result = rsaOaepCipher.encrypt(pubKeyDer, plaintext);
            } else {
                throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                        "Unsupported recipient key algorithm: " + keyAlgo) {};
            }

            long duration = System.currentTimeMillis() - startTime;
            log.info("证书加密成功: recipientType={}, keyAlgo={}, alg={}, duration={}ms",
                    recipient.getClass().getSimpleName(), keyAlgo, result.alg(), duration);
            cryptoMetrics.recordCertencEncrypt(duration);
            return result;
        } catch (CryptoException e) {
            cryptoMetrics.recordError();
            log.error("证书加密失败: recipientType={}", recipient.getClass().getSimpleName(), e);
            throw e;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("证书加密失败: recipientType={}", recipient.getClass().getSimpleName(), e);
            throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                    "encryptFor failed", e) {};
        }
    }

    @Override
    public byte[] wrapKeyFor(Recipient recipient, byte[] keyMaterial) {
        Objects.requireNonNull(recipient, "recipient must not be null");
        Objects.requireNonNull(keyMaterial, "keyMaterial must not be null");
        long startTime = System.currentTimeMillis();
        try {
            byte[] pubKeyDer = resolveRecipientPublicKey(recipient);
            String keyAlgo = detectKeyAlgorithm(pubKeyDer);

            byte[] result;
            if ("EC".equals(keyAlgo)) {
                result = eciesCipher.wrapKey(pubKeyDer);
            } else if ("RSA".equals(keyAlgo)) {
                result = rsaOaepCipher.wrapKey(pubKeyDer, keyMaterial);
            } else {
                throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                        "Unsupported recipient key algorithm: " + keyAlgo) {};
            }

            long duration = System.currentTimeMillis() - startTime;
            log.info("密钥封装成功: recipientType={}, keyAlgo={}, duration={}ms",
                    recipient.getClass().getSimpleName(), keyAlgo, duration);
            cryptoMetrics.recordCertencWrapKey(duration);
            return result;
        } catch (CryptoException e) {
            cryptoMetrics.recordError();
            log.error("密钥封装失败: recipientType={}", recipient.getClass().getSimpleName(), e);
            throw e;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("密钥封装失败: recipientType={}", recipient.getClass().getSimpleName(), e);
            throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                    "wrapKeyFor failed", e) {};
        }
    }

    /**
     * 解析收方公钥 SPKI DER
     */
    private byte[] resolveRecipientPublicKey(Recipient recipient) {
        if (recipient instanceof Recipient.CertRecipient cr) {
            return extractPublicKeyFromCert(cr.certDer());
        } else if (recipient instanceof Recipient.PublicKeyRecipient pkr) {
            return pkr.spki();
        } else if (recipient instanceof Recipient.SubjectRecipient sr) {
            CertificateEvidence evidence = resolveSubjectToEvidence(sr);
            if (evidence.hasSpki()) {
                return evidence.spki();
            }
            return extractPublicKeyFromCert(evidence.certificateDer());
        } else {
            throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                    "Unsupported recipient type: " + recipient.getClass().getName()) {};
        }
    }

    /**
     * 从证书 DER 或公钥 SPKI DER 提取公钥 SPKI DER
     * <p>
     * 先尝试解析为 X.509 证书；若失败则视为原始 SPKI 直接返回。
     */
    private byte[] extractPublicKeyFromCert(byte[] certOrKeyDer) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(certOrKeyDer));
            return cert.getPublicKey().getEncoded();
        } catch (Exception notCert) {
            return certOrKeyDer;
        }
    }

    /**
     * 经统一证书解析门面把主体/序列号解析为已校验证据（FW-SEC-DSN-CR-012 §4.1）。
     * <p>
     * 主体走显式 {@link CertificateSubjectRef}，序列号走 certSerial；
     * 解析顺序与校验由 {@link CertResolver} / {@link CertificateEvidenceValidator} 统一承担。
     */
    private CertificateEvidence resolveSubjectToEvidence(Recipient.SubjectRecipient sr) {
        if (certResolver == null) {
            throw new CryptoDependencyUnavailableException(
                    "CertResolver not configured; cannot resolve recipient certificate");
        }
        DeviceCertificateRef ref;
        switch (sr.type()) {
            case VIN -> ref = DeviceCertificateRef.ofSubject(CertificateSubjectRef.ofVehicle(sr.value()));
            case DEVICE -> ref = DeviceCertificateRef.ofSubject(CertificateSubjectRef.ofDevice(sr.value()));
            case USER -> ref = DeviceCertificateRef.ofSubject(CertificateSubjectRef.ofUser(sr.value()));
            case SERIAL -> ref = DeviceCertificateRef.ofSerial(sr.value());
            default -> throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                    "Unsupported subject type: " + sr.type()) {};
        }
        CertificateResolvePolicy policy = CertificateResolvePolicy.certEncryption();
        CertificateEvidence evidence = certResolver.resolve(ref, policy);
        if (evidenceValidator != null) {
            evidence = evidenceValidator.validate(evidence, ref, policy);
        }
        return evidence;
    }

    /**
     * 检测公钥算法（EC / RSA / Ed25519）
     */
    private String detectKeyAlgorithm(byte[] spkiDer) {
        for (String algo : new String[]{"EC", "RSA", "Ed25519"}) {
            try {
                KeyFactory kf = KeyFactory.getInstance(algo);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(spkiDer);
                PublicKey key = kf.generatePublic(keySpec);
                return key.getAlgorithm();
            } catch (Exception ignored) {
            }
        }
        throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                "Unable to determine recipient public key algorithm") {};
    }
}
