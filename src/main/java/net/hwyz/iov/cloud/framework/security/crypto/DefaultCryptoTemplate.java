package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.kdf.SessionKdf;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * CryptoTemplate默认实现
 */
@Component
public class DefaultCryptoTemplate implements CryptoTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultCryptoTemplate.class);

    private final DeviceResolver deviceResolver;
    private final KeyCache keyCache;
    private final AeadCipher aeadCipher;
    private final EnvelopeCodec envelopeCodec;
    private final CryptoMetrics cryptoMetrics;
    private final KmsClient kmsClient;

    public DefaultCryptoTemplate(DeviceResolver deviceResolver, KeyCache keyCache,
                                 AeadCipher aeadCipher, EnvelopeCodec envelopeCodec,
                                 CryptoMetrics cryptoMetrics, KmsClient kmsClient) {
        this.deviceResolver = deviceResolver;
        this.keyCache = keyCache;
        this.aeadCipher = aeadCipher;
        this.envelopeCodec = envelopeCodec;
        this.cryptoMetrics = cryptoMetrics;
        this.kmsClient = kmsClient;
    }

    @Override
    public byte[] encrypt(String vin, BizType bizType, byte[] plaintext) {
        long startTime = System.currentTimeMillis();
        try {
            if (bizType.cryptoMode() == BizType.CryptoMode.ENVELOPE && !bizType.supportsData()) {
                throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                        "BizType does not support data encryption: " + bizType.name()) {};
            }

            byte[] result;
            if (bizType.cryptoMode() == BizType.CryptoMode.SESSION) {
                result = encryptSession(vin, bizType, plaintext);
                long duration = System.currentTimeMillis() - startTime;
                log.info("SESSION加密成功: vin={}, bizType={}, duration={}ms", vin, bizType.name(), duration);
                cryptoMetrics.recordSessionEncrypt(duration);
            } else {
                result = encryptEnvelope(vin, bizType, plaintext);
                long duration = System.currentTimeMillis() - startTime;
                log.info("加密成功: vin={}, bizType={}, duration={}ms", vin, bizType.name(), duration);
                cryptoMetrics.recordEncrypt(duration);
            }
            return result;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("加密失败: vin={}, bizType={}", vin, bizType.name(), e);
            throw e;
        }
    }

    @Override
    public byte[] decrypt(byte[] cipherPayload) {
        long startTime = System.currentTimeMillis();
        try {
            CipherPayload payload = envelopeCodec.decode(cipherPayload);

            byte[] result;
            if (payload.getMode() == 1) {
                result = decryptSession(payload);
                long duration = System.currentTimeMillis() - startTime;
                log.info("SESSION解密成功: keyName={}, duration={}ms",
                        payload.getHeader().getKeyId(), duration);
                cryptoMetrics.recordSessionDecrypt(duration);
            } else {
                result = decryptEnvelope(payload);
                long duration = System.currentTimeMillis() - startTime;
                log.info("解密成功: keyId={}, keyVersion={}, duration={}ms",
                        payload.getHeader().getKeyId(), payload.getHeader().getKeyVersion(), duration);
                cryptoMetrics.recordDecrypt(duration);
            }
            return result;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("解密失败", e);
            throw e;
        }
    }

    private byte[] encryptEnvelope(String vin, BizType bizType, byte[] plaintext) {
        String deviceSn = deviceResolver.resolveDeviceSn(vin, bizType);
        CachedDataKey dataKey = keyCache.get(deviceSn, bizType);
        byte[] iv = aeadCipher.generateIv();

        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId(dataKey.getKeyId());
        header.setKeyVersion(dataKey.getKeyVersion());
        header.setAlg("AES_256_GCM");
        header.setIv(iv);
        header.setMode(0);

        byte[] aad = envelopeCodec.encode(header, new byte[0]);
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dataKey.getDekPlaintext(), iv, aad);
        return envelopeCodec.encode(header, ciphertext);
    }

    private byte[] decryptEnvelope(CipherPayload payload) {
        EnvelopeHeader header = payload.getHeader();
        CachedDataKey dataKey = keyCache.get(header.getKeyId(), header.getKeyVersion());
        byte[] aad = envelopeCodec.encode(header, new byte[0]);
        return aeadCipher.decrypt(payload.getCiphertext(), dataKey.getDekPlaintext(), header.getIv(), aad);
    }

    private byte[] encryptSession(String vin, BizType bizType, byte[] plaintext) {
        Objects.requireNonNull(bizType.prov(), "SESSION bizType must have prov (keyName)");
        String keyName = bizType.prov().keyName();
        String normalizedVin = vin.trim().toUpperCase();

        byte[] root = kmsClient.deriveSessionRoot(keyName, normalizedVin);
        byte[] salt = SessionKdf.generateSalt();
        byte[] info = SessionKdf.buildInfo("default");
        byte[] sessionKey = SessionKdf.deriveSessionKey(root, salt, info);
        byte[] nonce = aeadCipher.generateIv();

        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId(keyName);
        header.setAlg("AES_256_GCM");
        header.setIv(nonce);
        header.setMode(1);
        header.setSalt(salt);

        byte[] aad = envelopeCodec.encode(header, new byte[0], 1);
        byte[] ciphertext = aeadCipher.encrypt(plaintext, sessionKey, nonce, aad);
        return envelopeCodec.encode(header, ciphertext, 1);
    }

    private byte[] decryptSession(CipherPayload payload) {
        EnvelopeHeader header = payload.getHeader();
        String keyName = header.getKeyId();
        byte[] salt = header.getSalt();
        byte[] nonce = header.getIv();

        byte[] root = kmsClient.deriveSessionRoot(keyName, null);
        byte[] info = SessionKdf.buildInfo("default");
        byte[] sessionKey = SessionKdf.deriveSessionKey(root, salt, info);

        byte[] aad = envelopeCodec.encode(header, new byte[0], 1);
        return aeadCipher.decrypt(payload.getCiphertext(), sessionKey, nonce, aad);
    }
}
