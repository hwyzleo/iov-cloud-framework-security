package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;

/**
 * 证书解析能力关闭时的 fail-closed 实现（FW-SEC-DSN-CR-012 §5/§8）。
 * <p>
 * 当 {@code crypto.pki.certificate-resolution.enabled=false} 时装配，任何解析请求一律
 * fail-closed 抛出 {@link CryptoDependencyUnavailableException}，<b>不</b>创建可误用的
 * Noop / 放行实现，也不静默回退到未校验材料。
 */
public class FailClosedCertResolver implements CertResolver {

    private static final String MSG = "CertResolver is disabled: set crypto.pki.certificate-resolution.enabled=true "
            + "and configure crypto.pki.certificate-resolution.trust-anchors-pem to enable certificate resolution.";

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

    @Override
    public CertificateEvidence resolve(DeviceCertificateRef ref, CertificateResolvePolicy policy) {
        throw new CryptoDependencyUnavailableException(MSG);
    }
}
