package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyDirectoryUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyNotFoundException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyStateNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyDescriptor;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.CryptoKeyState;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.DeviceKeyContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.KeyOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * VMD 业务密钥目录解析器默认实现（FW-SEC-DSN-CR-009 §4）。
 * <p>
 * 委托 {@link VmdBusinessKeyDirectoryClient}（消费方以 Feign 接入 VMD Service API，
 * 负责调用方/业务域/用途授权与唯一 ACTIVE 权威）；framework 在此基础上执行 fail-closed 契约：
 * <ul>
 *   <li>resolveActive：空/状态不一致抛目录异常；非 ACTIVE 拒绝</li>
 *   <li>resolveByKeyId：空/不存在抛 BusinessKeyNotFoundException；REVOKED/EXPIRED 拒绝；
 *       DEPRECATED 以 decryptUntil 解密窗口作权威判断</li>
 * </ul>
 */
public class DefaultVmdBusinessKeyDirectoryResolver implements BusinessKeyDirectoryResolver {

    private static final Logger log = LoggerFactory.getLogger(DefaultVmdBusinessKeyDirectoryResolver.class);

    private final VmdBusinessKeyDirectoryClient client;
    private final CryptoMetrics cryptoMetrics;

    public DefaultVmdBusinessKeyDirectoryResolver(VmdBusinessKeyDirectoryClient client,
                                                  CryptoMetrics cryptoMetrics) {
        this.client = client;
        this.cryptoMetrics = cryptoMetrics;
    }

    @Override
    public BusinessKeyDescriptor resolveActive(DeviceKeyContext context) {
        long startTime = System.currentTimeMillis();
        try {
            BusinessKeyDescriptor descriptor = client.resolveActive(context);
            validateActive(descriptor, context);
            record(startTime);
            return descriptor;
        } catch (BusinessKeyDirectoryUnavailableException | BusinessKeyStateNotAllowedException e) {
            throw e;
        } catch (Exception e) {
            log.error("业务密钥目录解析失败（resolveActive）: deviceSn={}, bizType={}",
                    context != null ? context.deviceSn() : null,
                    context != null && context.bizType() != null ? context.bizType().name() : null, e);
            throw new BusinessKeyDirectoryUnavailableException(
                    "业务密钥目录不可用（resolveActive）: deviceSn=" + (context != null ? context.deviceSn() : null), e);
        }
    }

    @Override
    public BusinessKeyDescriptor resolveByKeyId(String keyId, KeyOperation operation) {
        long startTime = System.currentTimeMillis();
        try {
            BusinessKeyDescriptor descriptor = client.resolveByKeyId(keyId, operation);
            validateDecrypt(descriptor, keyId);
            record(startTime);
            return descriptor;
        } catch (BusinessKeyNotFoundException | BusinessKeyStateNotAllowedException
                 | BusinessKeyDirectoryUnavailableException e) {
            throw e;
        } catch (Exception e) {
            log.error("业务密钥目录解析失败（resolveByKeyId）: keyId={}, operation={}", keyId, operation, e);
            throw new BusinessKeyDirectoryUnavailableException(
                    "业务密钥目录不可用（resolveByKeyId）: keyId=" + keyId, e);
        }
    }

    private void validateActive(BusinessKeyDescriptor descriptor, DeviceKeyContext context) {
        if (descriptor == null) {
            throw new BusinessKeyDirectoryUnavailableException(
                    "目录返回空 ACTIVE（设备无活跃业务密钥）: deviceSn="
                            + (context != null ? context.deviceSn() : null));
        }
        if (descriptor.state() != CryptoKeyState.ACTIVE) {
            throw new BusinessKeyStateNotAllowedException(
                    "resolveActive 仅接受唯一 ACTIVE，状态不一致 fail-closed: keyId=" + descriptor.keyId()
                            + ", state=" + descriptor.state());
        }
    }

    private void validateDecrypt(BusinessKeyDescriptor descriptor, String keyId) {
        if (descriptor == null) {
            throw new BusinessKeyNotFoundException("业务密钥不存在: keyId=" + keyId);
        }
        if (descriptor.state() == CryptoKeyState.REVOKED || descriptor.state() == CryptoKeyState.EXPIRED) {
            throw new BusinessKeyStateNotAllowedException(
                    "业务密钥已吊销/过期，拒绝解密: keyId=" + keyId + ", state=" + descriptor.state());
        }
        if (descriptor.state() == CryptoKeyState.DEPRECATED) {
            if (descriptor.decryptUntil() != null && Instant.now().isAfter(descriptor.decryptUntil())) {
                throw new BusinessKeyStateNotAllowedException(
                        "DEPRECATED 已超解密窗口，拒绝解密: keyId=" + keyId
                                + ", decryptUntil=" + descriptor.decryptUntil());
            }
        }
    }

    private void record(long startTime) {
        if (cryptoMetrics != null) {
            cryptoMetrics.recordBusinessKeyDirectory(System.currentTimeMillis() - startTime);
        }
    }
}
