package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DeviceRecipient;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * DataKeyDistributionTemplate 默认实现（CR-005）
 * <p>
 * 取 {@code (device_sn, 业务域)} 活跃 DATA 密钥、用收方设备公钥/证书封装下发。
 * 校验 {@code bizType.supportsData == true}（对称于 {@link DefaultCryptoTemplate}，而非 {@code prov != null}），
 * 否则 fail-closed。
 * <p>
 * 幂等：同 {@code (device_sn, 业务域, 用途)} 有效期内返回同一活跃 keyId（由 KMS 侧保证）。
 */
public class DefaultDataKeyDistributionTemplate implements DataKeyDistributionTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultDataKeyDistributionTemplate.class);

    private final KmsClient kmsClient;
    private final CryptoMetrics cryptoMetrics;
    private final DeviceResolver deviceResolver;

    public DefaultDataKeyDistributionTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics,
                                               DeviceResolver deviceResolver) {
        this.kmsClient = kmsClient;
        this.cryptoMetrics = cryptoMetrics;
        this.deviceResolver = deviceResolver;
    }

    @Override
    public WrappedDataKey issueActiveKeyForDevice(String deviceSnOrVin, BizType bizType, DeviceRecipient recipient) {
        long startTime = System.currentTimeMillis();
        try {
            Objects.requireNonNull(bizType, "bizType must not be null");
            Objects.requireNonNull(deviceSnOrVin, "deviceSnOrVin must not be null");
            Objects.requireNonNull(recipient, "recipient must not be null");
            validateDataCapability(bizType);

            String deviceSn = resolveDeviceSn(deviceSnOrVin, bizType);
            String keyName = bizType.prov() != null ? bizType.prov().keyName() : "default";

            WrappedDataKey result = kmsClient.wrapActiveDataKeyForDevice(
                    keyName, deviceSn, bizType, recipient.certSerial());

            long duration = System.currentTimeMillis() - startTime;
            log.info("数据密钥下发成功: deviceSn={}, bizType={}, keyId={}, certSerial={}, duration={}ms",
                    deviceSn, bizType.name(), result.getKeyId(), recipient.certSerial(), duration);
            cryptoMetrics.recordKeyprovIssue(duration);

            return result;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("数据密钥下发失败: deviceSnOrVin={}, bizType={}, certSerial={}",
                    deviceSnOrVin, bizType.name(),
                    recipient != null ? recipient.certSerial() : "null", e);
            throw e;
        }
    }

    private String resolveDeviceSn(String deviceSnOrVin, BizType bizType) {
        if (deviceSnOrVin == null || deviceSnOrVin.isBlank()) {
            throw new CryptoException(CryptoException.Reason.DEVICE_UNBOUND,
                    "deviceSnOrVin is null or blank") {};
        }

        if (looksLikeVin(deviceSnOrVin)) {
            if (deviceResolver == null) {
                throw new CryptoDependencyUnavailableException(
                        "DeviceResolver unavailable, VIN lookup requires VMD/TSP. vin=" + deviceSnOrVin);
            }
            return deviceResolver.resolveDeviceSn(deviceSnOrVin, bizType);
        }
        return deviceSnOrVin.trim();
    }

    private boolean looksLikeVin(String s) {
        String trimmed = s.trim();
        return trimmed.length() >= 10 && trimmed.length() <= 17
                && trimmed.matches("[A-Za-z0-9]+");
    }

    private void validateDataCapability(BizType bizType) {
        if (!bizType.supportsData()) {
            throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                    "BizType does not support data key distribution (supportsData=false): " + bizType.name()) {};
        }
    }
}
