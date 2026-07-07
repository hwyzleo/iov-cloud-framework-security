package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

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

    public DefaultCryptoTemplate(DeviceResolver deviceResolver, KeyCache keyCache,
                                 AeadCipher aeadCipher, EnvelopeCodec envelopeCodec,
                                 CryptoMetrics cryptoMetrics) {
        this.deviceResolver = deviceResolver;
        this.keyCache = keyCache;
        this.aeadCipher = aeadCipher;
        this.envelopeCodec = envelopeCodec;
        this.cryptoMetrics = cryptoMetrics;
    }

    @Override
    public byte[] encrypt(String vin, BizType bizType, byte[] plaintext) {
        long startTime = System.currentTimeMillis();
        try {
            // 验证bizType支持信封加解密（supportsData），不支持则 fail-closed
            if (!bizType.supportsData()) {
                throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                        "BizType does not support data encryption: " + bizType.name()) {};
            }

            // 1. 解析设备SN
            String deviceSn = deviceResolver.resolveDeviceSn(vin, bizType);

            // 2. 获取数据密钥
            CachedDataKey dataKey = keyCache.get(deviceSn, bizType);

            // 3. 生成IV
            byte[] iv = aeadCipher.generateIv();

            // 4. 构建信封头
            EnvelopeHeader header = new EnvelopeHeader();
            header.setVer(1);
            header.setKeyId(dataKey.getKeyId());
            header.setKeyVersion(dataKey.getKeyVersion());
            header.setAlg("AES_256_GCM");
            header.setIv(iv);

            // 5. 编码信封头作为AAD
            byte[] aad = envelopeCodec.encode(header, new byte[0]);

            // 6. 加密
            byte[] ciphertext = aeadCipher.encrypt(plaintext, dataKey.getDekPlaintext(), iv, aad);

            // 7. 返回完整payload
            byte[] result = envelopeCodec.encode(header, ciphertext);

            // 记录审计日志
            long duration = System.currentTimeMillis() - startTime;
            log.info("加密成功: vin={}, bizType={}, keyId={}, duration={}ms",
                    vin, bizType.name(), dataKey.getKeyId(), duration);
            cryptoMetrics.recordEncrypt(duration);

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
            // 1. 解码信封头
            CipherPayload payload = envelopeCodec.decode(cipherPayload);
            EnvelopeHeader header = payload.getHeader();

            // 2. 获取数据密钥
            CachedDataKey dataKey = keyCache.get(header.getKeyId(), header.getKeyVersion());

            // 3. 编码信封头作为AAD
            byte[] aad = envelopeCodec.encode(header, new byte[0]);

            // 4. 解密
            byte[] result = aeadCipher.decrypt(payload.getCiphertext(), dataKey.getDekPlaintext(), header.getIv(), aad);

            // 记录审计日志
            long duration = System.currentTimeMillis() - startTime;
            log.info("解密成功: keyId={}, keyVersion={}, duration={}ms",
                    header.getKeyId(), header.getKeyVersion(), duration);
            cryptoMetrics.recordDecrypt(duration);

            return result;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("解密失败", e);
            throw e;
        }
    }
}
