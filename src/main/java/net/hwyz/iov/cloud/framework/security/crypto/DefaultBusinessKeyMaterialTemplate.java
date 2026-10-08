package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsCreateKeyCommand;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsKeyMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsKeyMetadata;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsKeyReference;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsRecipient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsRevocationResult;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyNotFoundException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyRevocationFailedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.BusinessKeyWrapFailedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyCreateRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyMetadata;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RevocationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RevocationResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrappedBusinessKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * 运行期业务密钥密码学材料门面默认实现（FW-SEC-DSN-CR-009 §3/§4.5）。
 * <p>
 * 仅操作显式 {@link BusinessKeyRef}，委托 {@link KmsClient} 完成 create/wrap/getMetadata/revoke。
 * 创建/吊销结果未知抛 {@link CryptoOperationOutcomeUnknownException}（须原幂等键对账），
 * 不换键重建；Wrapped Key 不持久化、不进日志或事件。
 */
public class DefaultBusinessKeyMaterialTemplate implements BusinessKeyMaterialTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultBusinessKeyMaterialTemplate.class);

    private final KmsClient kmsClient;
    private final CryptoMetrics cryptoMetrics;
    private final String provider;

    public DefaultBusinessKeyMaterialTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics,
                                              CryptoProperties properties) {
        this.kmsClient = kmsClient;
        this.cryptoMetrics = cryptoMetrics;
        this.provider = properties.getProvisioning().getProvider();
    }

    @Override
    public BusinessKeyMaterial create(BusinessKeyCreateRequest request) {
        long startTime = System.currentTimeMillis();
        Objects.requireNonNull(request, "request must not be null");
        Objects.requireNonNull(request.bizType(), "bizType must not be null");
        Objects.requireNonNull(request.policy(), "policy must not be null");
        try {
            KmsCreateKeyCommand command = new KmsCreateKeyCommand(
                    request.bizType().name(),
                    request.policy().algorithm(),
                    request.policy().keySpec(),
                    request.idempotencyKey(),
                    request.auditContext());
            KmsKeyMaterial material = kmsClient.createDataKey(command);

            long duration = System.currentTimeMillis() - startTime;
            log.info("业务密钥材料创建成功: bizType={}, keyId={}, kmsKeyRef={}, kmsKeyVersion={}, duration={}ms",
                    request.bizType().name(), material.keyId(), material.kmsKeyRef(),
                    material.kmsKeyVersion(), duration);
            cryptoMetrics.recordBusinessKeyCreate(duration);

            return new BusinessKeyMaterial(
                    material.keyId(), material.kmsKeyRef(), material.kmsKeyVersion(),
                    material.provider() != null ? material.provider() : provider,
                    material.algorithm(), material.keySpec(), material.validFrom(), material.validTo());
        } catch (BusinessKeyIdempotencyConflictException | CryptoOperationOutcomeUnknownException e) {
            throw e;
        } catch (CryptoException e) {
            log.error("业务密钥材料创建失败: bizType={}, idempotencyKey={}",
                    request.bizType().name(), request.idempotencyKey(), e);
            throw e;
        } catch (Exception e) {
            // 请求可能已发送但结果未知：保守抛未知结果，调用方须用原幂等键对账
            log.error("业务密钥材料创建结果未知: bizType={}, idempotencyKey={}",
                    request.bizType().name(), request.idempotencyKey(), e);
            throw new CryptoOperationOutcomeUnknownException(
                    "创建业务密钥材料结果未知（请求可能已发送），须用原幂等键对账: idempotencyKey="
                            + request.idempotencyKey(), e);
        }
    }

    @Override
    public WrappedBusinessKey wrap(BusinessKeyRef keyRef, RecipientRef recipient, WrapContext context) {
        long startTime = System.currentTimeMillis();
        Objects.requireNonNull(keyRef, "keyRef must not be null");
        Objects.requireNonNull(recipient, "recipient must not be null（无隐式收方推断，RD-009-2）");
        Objects.requireNonNull(context, "context must not be null");

        WrapMode expectedMode = recipient.wrapMode();
        if (context.mode() != null && context.mode() != expectedMode) {
            throw new BusinessKeyWrapFailedException(
                    "WrapMode 不一致: context=" + context.mode() + ", recipient 推导=" + expectedMode
                            + "（FW-SEC-DSN-CR-009 §3）");
        }
        if (expectedMode == WrapMode.DEVICE_ROOT_KEK && !(recipient instanceof RecipientRef.DeviceRoot)) {
            throw new BusinessKeyWrapFailedException(
                    "DEVICE_ROOT_KEK 仅可在显式可信 wrappingKeyRef 下使用，不得从 deviceSn 猜测（RD-009-3）");
        }

        try {
            KmsWrappedKey wrapped = kmsClient.wrapKey(
                    new KmsKeyReference(keyRef.keyId(), keyRef.kmsKeyRef()),
                    toKmsRecipient(recipient));

            long duration = System.currentTimeMillis() - startTime;
            log.info("业务密钥封装成功: keyId={}, mode={}, wrappedBytes={}, duration={}ms",
                    keyRef.keyId(), expectedMode, wrapped.wrapped() == null ? 0 : wrapped.wrapped().length, duration);
            cryptoMetrics.recordBusinessKeyWrap(duration);

            // 瞬时结果，使用后即释放；不写入结果存储/日志/事件
            return new WrappedBusinessKey(
                    wrapped.wrapped(), wrapped.keyId(), wrapped.kmsKeyVersion(),
                    wrapped.algorithm(), wrapped.expiry(), wrapped.parameters());
        } catch (BusinessKeyWrapFailedException e) {
            throw e;
        } catch (CryptoException e) {
            log.error("业务密钥封装失败: keyId={}, mode={}", keyRef.keyId(), expectedMode, e);
            throw e;
        } catch (Exception e) {
            log.error("业务密钥封装异常: keyId={}, mode={}", keyRef.keyId(), expectedMode, e);
            throw new BusinessKeyWrapFailedException(
                    "按收方模式封装失败: keyId=" + keyRef.keyId() + ", mode=" + expectedMode, e);
        }
    }

    @Override
    public BusinessKeyMetadata getMetadata(BusinessKeyRef keyRef) {
        long startTime = System.currentTimeMillis();
        Objects.requireNonNull(keyRef, "keyRef must not be null");
        try {
            KmsKeyMetadata meta = kmsClient.getKeyMetadata(
                    new KmsKeyReference(keyRef.keyId(), keyRef.kmsKeyRef()));

            long duration = System.currentTimeMillis() - startTime;
            log.info("业务密钥元数据查询成功: keyId={}, state={}, kmsKeyVersion={}, duration={}ms",
                    keyRef.keyId(), meta.state(), meta.kmsKeyVersion(), duration);
            cryptoMetrics.recordBusinessKeyMetadata(duration);

            return new BusinessKeyMetadata(
                    meta.keyId(), meta.kmsKeyRef(), meta.kmsKeyVersion(),
                    meta.provider() != null ? meta.provider() : provider,
                    meta.algorithm(), meta.keySpec(), meta.state(),
                    meta.validFrom(), meta.validTo(), meta.decryptUntil());
        } catch (BusinessKeyNotFoundException e) {
            throw e;
        } catch (CryptoException e) {
            log.error("业务密钥元数据查询失败: keyId={}", keyRef.keyId(), e);
            throw e;
        } catch (Exception e) {
            throw new CryptoOperationOutcomeUnknownException(
                    "业务密钥元数据查询结果未知: keyId=" + keyRef.keyId(), e);
        }
    }

    @Override
    public RevocationResult revoke(BusinessKeyRef keyRef, RevocationRequest request) {
        long startTime = System.currentTimeMillis();
        Objects.requireNonNull(keyRef, "keyRef must not be null");
        Objects.requireNonNull(request, "request must not be null");
        Objects.requireNonNull(request.idempotencyKey(), "idempotencyKey must not be null");
        try {
            KmsRevocationResult result = kmsClient.revokeKey(
                    new KmsKeyReference(keyRef.keyId(), keyRef.kmsKeyRef()),
                    request.reason(), request.idempotencyKey());

            long duration = System.currentTimeMillis() - startTime;
            log.info("业务密钥吊销成功: keyId={}, state={}, duration={}ms",
                    keyRef.keyId(), result.state(), duration);
            cryptoMetrics.recordBusinessKeyRevoke(duration);

            return new RevocationResult(result.keyId(), result.state(), result.changedAt());
        } catch (BusinessKeyIdempotencyConflictException | CryptoOperationOutcomeUnknownException e) {
            // 结果未知：VMD 维持阻断使用并对账；framework 不得自动恢复可用
            throw e;
        } catch (CryptoException e) {
            log.error("业务密钥吊销失败: keyId={}", keyRef.keyId(), e);
            throw e;
        } catch (Exception e) {
            log.error("业务密钥吊销异常: keyId={}", keyRef.keyId(), e);
            throw new BusinessKeyRevocationFailedException(
                    "业务密钥吊销失败: keyId=" + keyRef.keyId(), e);
        }
    }

    private KmsRecipient toKmsRecipient(RecipientRef recipient) {
        if (recipient instanceof RecipientRef.DeviceCertificate c) {
            return KmsRecipient.deviceCertificate(c.certSerial());
        }
        if (recipient instanceof RecipientRef.PublicKey p) {
            return KmsRecipient.publicKey(p.spki());
        }
        if (recipient instanceof RecipientRef.RuntimeIdentity r) {
            return KmsRecipient.runtime(r.audience());
        }
        if (recipient instanceof RecipientRef.DeviceRoot d) {
            return KmsRecipient.deviceRoot(d.wrappingKeyRef());
        }
        throw new BusinessKeyWrapFailedException("未知收方类型: " + recipient.getClass().getName());
    }
}
