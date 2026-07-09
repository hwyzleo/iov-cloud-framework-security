package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;

/**
 * 默认证书解析器（fail-closed 桩）
 * <p>
 * framework 不自带证书目录，未注入 PKI 实现时一律抛 {@link CryptoDependencyUnavailableException}。
 * 消费方按需提供 {@link CertResolver} Bean 覆盖。
 */
public class DefaultCertResolver implements CertResolver {

    private static final String MSG = "CertResolver not configured. Please provide a PKI/cert-directory CertResolver bean.";

    @Override
    public byte[] resolveByVin(String vin) {
        throw new CryptoDependencyUnavailableException(MSG);
    }

    @Override
    public byte[] resolveByDeviceSn(String deviceSn) {
        throw new CryptoDependencyUnavailableException(MSG);
    }

    @Override
    public byte[] resolveByUid(String uid) {
        throw new CryptoDependencyUnavailableException(MSG);
    }

    @Override
    public byte[] resolveBySerial(String certSerial) {
        throw new CryptoDependencyUnavailableException(MSG);
    }
}
