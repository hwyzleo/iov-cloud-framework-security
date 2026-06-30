package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.springframework.stereotype.Component;

/**
 * CryptoTemplate默认实现
 */
@Component
public class DefaultCryptoTemplate implements CryptoTemplate {

    private final DeviceResolver deviceResolver;
    private final KeyCache keyCache;
    private final AeadCipher aeadCipher;
    private final EnvelopeCodec envelopeCodec;

    public DefaultCryptoTemplate(DeviceResolver deviceResolver, KeyCache keyCache,
                                 AeadCipher aeadCipher, EnvelopeCodec envelopeCodec) {
        this.deviceResolver = deviceResolver;
        this.keyCache = keyCache;
        this.aeadCipher = aeadCipher;
        this.envelopeCodec = envelopeCodec;
    }

    @Override
    public byte[] encrypt(String vin, String bizDomain, byte[] plaintext) {
        String deviceSn = deviceResolver.resolveDeviceSn(vin, bizDomain);

        CachedDataKey dataKey = keyCache.get(deviceSn, bizDomain);

        byte[] iv = aeadCipher.generateIv();

        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId(dataKey.getKeyId());
        header.setKeyVersion(dataKey.getKeyVersion());
        header.setAlg("AES_256_GCM");
        header.setIv(iv);

        byte[] aad = envelopeCodec.encode(header, new byte[0]);

        byte[] ciphertext = aeadCipher.encrypt(plaintext, dataKey.getDekPlaintext(), iv, aad);

        return envelopeCodec.encode(header, ciphertext);
    }

    @Override
    public byte[] decrypt(byte[] cipherPayload) {
        CipherPayload payload = envelopeCodec.decode(cipherPayload);
        EnvelopeHeader header = payload.getHeader();

        CachedDataKey dataKey = keyCache.get(header.getKeyId(), header.getKeyVersion());

        byte[] aad = envelopeCodec.encode(header, new byte[0]);

        return aeadCipher.decrypt(payload.getCiphertext(), dataKey.getDekPlaintext(), header.getIv(), aad);
    }
}
