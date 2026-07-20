package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiDependencyUnavailableException;

/**
 * 默认PKI客户端实现
 * 当没有配置PKI端点时使用，调用时会抛出异常
 */
public class DefaultPkiClient implements PkiClient {

    @Override
    public ApplyResponse submit(ApplyCommand command) {
        throw new PkiDependencyUnavailableException("PKI client not configured. Please set crypto.pki.endpoint property.");
    }

    @Override
    public StatusResponse getStatus(String requestId) {
        throw new PkiDependencyUnavailableException("PKI client not configured. Please set crypto.pki.endpoint property.");
    }

    @Override
    public CertificateResponse getCertificate(String requestId) {
        throw new PkiDependencyUnavailableException("PKI client not configured. Please set crypto.pki.endpoint property.");
    }

    @Override
    public CertificateResponse queryCertificate(String serialNumber) {
        throw new PkiDependencyUnavailableException("PKI client not configured. Please set crypto.pki.endpoint property.");
    }
}
