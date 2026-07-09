package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * SigningTemplate 默认实现（CR-006）
 * <p>
 * 以 KMS 托管的非对称私钥完成签名与验签；私钥永不出 KMS。
 * 密钥定位 = {@code BizType}（{@code prov.keyName} + {@code prov.anchor}）+ {@code KeyScope}（具体主体值）。
 * <p>
 * keyName 构建：
 * <ul>
 *   <li>ORG -> {@code prov.keyName}（全局一把）</li>
 *   <li>VEHICLE -> {@code prov.keyName + ":" + vin}</li>
 *   <li>DEVICE -> {@code prov.keyName + ":" + deviceSn}</li>
 *   <li>USER -> {@code prov.keyName + ":" + uid}</li>
 * </ul>
 * 校验：{@code supportsSigning}、{@code keyType==ASYMMETRIC}、KeyScope-anchor 匹配，否则 fail-closed。
 */
public class DefaultSigningTemplate implements SigningTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultSigningTemplate.class);
    private static final String KEY_NAME_SEPARATOR = ":";

    private final KmsClient kmsClient;
    private final CryptoMetrics cryptoMetrics;

    public DefaultSigningTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics) {
        this.kmsClient = kmsClient;
        this.cryptoMetrics = cryptoMetrics;
    }

    @Override
    public byte[] sign(BizType bizType, KeyScope scope, byte[] data) {
        Objects.requireNonNull(data, "data must not be null");
        validateSigningCapability(bizType, scope);
        String keyName = buildKmsKeyName(bizType, scope);
        long startTime = System.currentTimeMillis();
        try {
            byte[] signature = kmsClient.signWith(keyName, data, bizType.signAlgo());
            long duration = System.currentTimeMillis() - startTime;
            log.info("签名成功: bizType={}, keyName={}, algo={}, duration={}ms",
                    bizType.name(), keyName, bizType.signAlgo(), duration);
            cryptoMetrics.recordSigningSign(duration);
            return signature;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("签名失败: bizType={}, keyName={}", bizType.name(), keyName, e);
            throw e;
        }
    }

    @Override
    public byte[] getPublicKey(BizType bizType, KeyScope scope) {
        validateSigningCapability(bizType, scope);
        String keyName = buildKmsKeyName(bizType, scope);
        long startTime = System.currentTimeMillis();
        try {
            byte[] pubKey = kmsClient.getPublicKey(keyName);
            long duration = System.currentTimeMillis() - startTime;
            log.info("取公钥成功: bizType={}, keyName={}, duration={}ms",
                    bizType.name(), keyName, duration);
            cryptoMetrics.recordSigningSign(duration);
            return pubKey;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("取公钥失败: bizType={}, keyName={}", bizType.name(), keyName, e);
            throw e;
        }
    }

    @Override
    public boolean verify(BizType bizType, KeyScope scope, byte[] data, byte[] signature) {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(signature, "signature must not be null");
        validateSigningCapability(bizType, scope);
        String keyName = buildKmsKeyName(bizType, scope);
        long startTime = System.currentTimeMillis();
        try {
            boolean valid = kmsClient.verifyWith(keyName, data, signature, bizType.signAlgo());
            long duration = System.currentTimeMillis() - startTime;
            log.info("验签完成: bizType={}, keyName={}, valid={}, duration={}ms",
                    bizType.name(), keyName, valid, duration);
            cryptoMetrics.recordSigningVerify(duration);
            return valid;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("验签失败: bizType={}, keyName={}", bizType.name(), keyName, e);
            throw e;
        }
    }

    @Override
    public boolean verifyWith(byte[] certOrPublicKey, byte[] data, byte[] signature) {
        Objects.requireNonNull(certOrPublicKey, "certOrPublicKey must not be null");
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(signature, "signature must not be null");
        long startTime = System.currentTimeMillis();
        try {
            PublicKey publicKey = parsePublicKey(certOrPublicKey);
            String jcaAlgo = resolveJcaVerifyAlgo(publicKey);
            Signature verifier = Signature.getInstance(jcaAlgo);
            verifier.initVerify(publicKey);
            verifier.update(data);
            boolean valid = verifier.verify(signature);
            long duration = System.currentTimeMillis() - startTime;
            log.info("对方验签完成: algo={}, valid={}, duration={}ms", jcaAlgo, valid, duration);
            cryptoMetrics.recordSigningVerify(duration);
            return valid;
        } catch (CryptoException e) {
            cryptoMetrics.recordError();
            log.error("对方验签失败", e);
            throw e;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("对方验签失败", e);
            throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                    "verifyWith failed", e) {};
        }
    }

    /**
     * 构建 KMS keyName：ORG 为 prov.keyName，其余为 prov.keyName + ":" + subject
     */
    private String buildKmsKeyName(BizType bizType, KeyScope scope) {
        String base = bizType.prov().keyName();
        if (scope.anchor() == BizType.Anchor.ORG) {
            return base;
        }
        return base + KEY_NAME_SEPARATOR + scope.subject();
    }

    /**
     * 校验签名能力与作用域匹配
     */
    private void validateSigningCapability(BizType bizType, KeyScope scope) {
        Objects.requireNonNull(bizType, "bizType must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
        if (!bizType.supportsSigning()) {
            throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                    "BizType does not support signing (supportsSigning=false): " + bizType.name()) {};
        }
        if (bizType.keyType() != BizType.KeyType.ASYMMETRIC) {
            throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                    "BizType keyType must be ASYMMETRIC for signing, got " + bizType.keyType()
                            + " for bizType=" + bizType.name()) {};
        }
        if (bizType.prov() == null) {
            throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                    "BizType prov must not be null for signing: " + bizType.name()) {};
        }
        if (scope.anchor() != bizType.prov().anchor()) {
            throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                    "KeyScope anchor " + scope.anchor() + " does not match bizType anchor "
                            + bizType.prov().anchor() + " for bizType=" + bizType.name()) {};
        }
    }

    /**
     * 从证书 DER 或公钥 SPKI DER 解析出 PublicKey
     */
    private PublicKey parsePublicKey(byte[] certOrPublicKey) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(certOrPublicKey));
            return cert.getPublicKey();
        } catch (Exception notCert) {
            try {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(certOrPublicKey);
                KeyFactory kf = KeyFactory.getInstance("EC");
                return kf.generatePublic(keySpec);
            } catch (Exception notEc) {
                try {
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(certOrPublicKey);
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    return kf.generatePublic(keySpec);
                } catch (Exception notRsa) {
                    try {
                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(certOrPublicKey);
                        KeyFactory kf = KeyFactory.getInstance("Ed25519");
                        return kf.generatePublic(keySpec);
                    } catch (Exception e) {
                        throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                                "Failed to parse public key or certificate", e) {};
                    }
                }
            }
        }
    }

    /**
     * 根据公钥算法推断 JCA 验签算法名
     */
    private String resolveJcaVerifyAlgo(PublicKey publicKey) {
        String algo = publicKey.getAlgorithm();
        if ("EC".equals(algo)) {
            return "SHA256withECDSA";
        }
        if ("Ed25519".equals(algo) || "EdDSA".equals(algo)) {
            return "Ed25519";
        }
        if ("RSA".equals(algo)) {
            return "SHA256withRSA";
        }
        throw new CryptoException(CryptoException.Reason.INTEGRITY_VERIFICATION_FAILED,
                "Unsupported public key algorithm for verification: " + algo) {};
    }
}
