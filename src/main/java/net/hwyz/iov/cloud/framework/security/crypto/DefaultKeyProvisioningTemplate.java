package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.ProvisioningResult;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * KeyProvisioningTemplate 默认实现
 * <p>
 * 底层复用 {@link KmsClient} 通道原语（hmac / encryptWith / decryptWith），
 * 业务语义以 {@link BizType}（{@code prov != null}）枚举项传入。
 * <p>
 * <strong>派生取值由 {@code bizType.prov.anchor} 决定</strong>：
 * <ul>
 *   <li>{@code anchor=VEHICLE}（车级）→ {@code hmac(keyName, VIN)}，<strong>不解析设备</strong>
 *       （换 TBOX 不变、PRODUCE 建档 D16 阶段即可派生），仅 {@code deriveByVin}；</li>
 *   <li>{@code anchor=DEVICE}（设备级）→ 绑芯片：{@code deriveByVin} 先 VIN→device_sn 解析再
 *       {@code hmac(keyName, device_sn)}，{@code deriveByUid} 直接 {@code hmac(keyName, uid)}
 *       （两路指向同一芯片、同一秘密）；{@code deriveByUid} 仅接受 {@code anchor=DEVICE}。</li>
 * </ul>
 * <strong>封装/解封（by-reference，CR-004）</strong>：封装方法不传明文 material——内部串接
 * {@code hmac}（派生）+ {@code encryptWith}（封装），明文不出 KMS。封装收方恒为器件：
 * {@code *ByVin} 先解析设备、{@code *ByUid} 直指 {@code dev-{uid}}，与 anchor 无关。
 * {@code wrapByUid} 仅接受 {@code anchor=DEVICE}（VEHICLE 派生需 VIN）。
 * {@code wrapFor} 为跨设备封装：派生 {@code keyBizType@vinOrUid} 后以 {@code dev-{recipientUid}} 封装。
 * <p>
 * 派生公式与 KCV 由框架拥有，任一 KMS 调用不可用即 fail-closed 抛 {@link CryptoException}。
 */
public class DefaultKeyProvisioningTemplate implements KeyProvisioningTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultKeyProvisioningTemplate.class);

    private static final String DERIVE_ALGORITHM = "HMAC-SHA256";
    private static final String WRAP_ALGORITHM = "HMAC-SHA256+AES-256-GCM";
    private static final String KEY_SPEC = "256-bit";
    private static final int KCV_LENGTH = 4;
    private static final String DEV_KEY_PREFIX = "dev-";
    private static final String REF_SEPARATOR = ":";
    private static final String SCOPE_VIN = "vin";
    private static final String SCOPE_SN = "sn";

    private final KmsClient kmsClient;
    private final CryptoMetrics cryptoMetrics;
    private final String provider;
    private final DeviceResolver deviceResolver;

    public DefaultKeyProvisioningTemplate(KmsClient kmsClient, CryptoMetrics cryptoMetrics,
                                          CryptoProperties properties, DeviceResolver deviceResolver) {
        this.kmsClient = kmsClient;
        this.cryptoMetrics = cryptoMetrics;
        this.provider = properties.getProvisioning().getProvider();
        this.deviceResolver = deviceResolver;
    }

    // ==================== 派生 ====================

    @Override
    public ProvisioningResult deriveByVin(String vin, BizType bizType) {
        validateProvisionCapability(bizType);
        Objects.requireNonNull(vin, "vin must not be null");
        String normalizedVin = normalizeVin(vin);
        BizType.Prov prov = bizType.prov();
        if (prov.anchor() == BizType.Anchor.VEHICLE) {
            return doDerive(prov.keyName(), normalizedVin, bizType, "vin=" + normalizedVin, SCOPE_VIN);
        } else {
            String deviceSn = resolveDeviceSn(normalizedVin, bizType);
            return doDerive(prov.keyName(), deviceSn, bizType, "vin=" + normalizedVin + " (sn=" + deviceSn + ")", SCOPE_SN);
        }
    }

    @Override
    public ProvisioningResult deriveByUid(String uid, BizType bizType) {
        validateProvisionCapability(bizType);
        Objects.requireNonNull(uid, "uid must not be null");
        BizType.Prov prov = bizType.prov();
        if (prov.anchor() == BizType.Anchor.VEHICLE) {
            throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                    "deriveByUid only accepts anchor=DEVICE, got VEHICLE for bizType=" + bizType.name()) {};
        }
        String normalizedUid = normalizeUid(uid);
        return doDerive(prov.keyName(), normalizedUid, bizType, "uid=" + normalizedUid, SCOPE_SN);
    }

    private ProvisioningResult doDerive(String keyName, String identity, BizType bizType, String logCtx, String scope) {
        long startTime = System.currentTimeMillis();
        try {
            byte[] derived = kmsClient.hmac(keyName, identity.getBytes(StandardCharsets.UTF_8));
            long duration = System.currentTimeMillis() - startTime;
            log.info("派生成功: bizType={}, keyName={}, {} (identity={}), duration={}ms",
                    bizType.name(), keyName, logCtx, identity, duration);
            cryptoMetrics.recordProvisioningDerive(duration);
            return buildDeriveResult(keyName, scope, identity, derived);
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("派生失败: bizType={}, keyName={}, {}", bizType.name(), keyName, logCtx, e);
            throw e;
        }
    }

    // ==================== 封装（by-reference，CR-004） ====================

    @Override
    public ProvisioningResult wrapByVin(String vin, BizType bizType) {
        validateProvisionCapability(bizType);
        Objects.requireNonNull(vin, "vin must not be null");
        String normalizedVin = normalizeVin(vin);
        BizType.Prov prov = bizType.prov();
        String deviceSn = resolveDeviceSn(normalizedVin, bizType);
        byte[] identity = (prov.anchor() == BizType.Anchor.VEHICLE)
                ? normalizedVin.getBytes(StandardCharsets.UTF_8)
                : deviceSn.getBytes(StandardCharsets.UTF_8);
        String deriveCtx = (prov.anchor() == BizType.Anchor.VEHICLE)
                ? "vin=" + normalizedVin
                : "vin=" + normalizedVin + " (sn=" + deviceSn + ")";
        return doWrap(deviceSn, prov.keyName(), identity, bizType, deriveCtx);
    }

    @Override
    public ProvisioningResult wrapByUid(String uid, BizType bizType) {
        validateProvisionCapability(bizType);
        Objects.requireNonNull(uid, "uid must not be null");
        BizType.Prov prov = bizType.prov();
        if (prov.anchor() == BizType.Anchor.VEHICLE) {
            throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                    "wrapByUid only accepts anchor=DEVICE for by-reference wrap, got VEHICLE for bizType=" + bizType.name()) {};
        }
        String normalizedUid = normalizeUid(uid);
        return doWrap(normalizedUid, prov.keyName(), normalizedUid.getBytes(StandardCharsets.UTF_8),
                bizType, "uid=" + normalizedUid);
    }

    @Override
    public ProvisioningResult wrapFor(BizType keyBizType, String vinOrUid, String recipientUid) {
        validateProvisionCapability(keyBizType);
        Objects.requireNonNull(vinOrUid, "vinOrUid must not be null");
        Objects.requireNonNull(recipientUid, "recipientUid must not be null");
        BizType.Prov prov = keyBizType.prov();
        byte[] identity;
        String deriveCtx;
        if (prov.anchor() == BizType.Anchor.VEHICLE) {
            String normalizedVin = normalizeVin(vinOrUid);
            identity = normalizedVin.getBytes(StandardCharsets.UTF_8);
            deriveCtx = "vin=" + normalizedVin;
        } else {
            String normalizedUid = normalizeUid(vinOrUid);
            identity = normalizedUid.getBytes(StandardCharsets.UTF_8);
            deriveCtx = "uid=" + normalizedUid;
        }
        String normalizedRecipient = normalizeUid(recipientUid);
        return doWrapFor(normalizedRecipient, prov.keyName(), identity, keyBizType, deriveCtx);
    }

    /**
     * by-reference 封装：内部 hmac 派生 → encryptWith 封装，明文不出 KMS
     */
    private ProvisioningResult doWrap(String deviceSn, String keyName, byte[] identity,
                                      BizType bizType, String deriveCtx) {
        String wrapKeyName = DEV_KEY_PREFIX + deviceSn;
        long startTime = System.currentTimeMillis();
        try {
            byte[] derived = kmsClient.hmac(keyName, identity);
            byte[] wrapped = kmsClient.encryptWith(wrapKeyName, derived);
            long duration = System.currentTimeMillis() - startTime;
            log.info("封装成功(by-ref): bizType={}, keyName={}, wrapKey={}, {} (sn={}), duration={}ms",
                    bizType.name(), keyName, wrapKeyName, deriveCtx, deviceSn, duration);
            cryptoMetrics.recordProvisioningWrap(duration);
            return buildWrapResult(wrapKeyName, derived, wrapped);
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("封装失败(by-ref): bizType={}, keyName={}, wrapKey={}, {}", bizType.name(), keyName, wrapKeyName, deriveCtx, e);
            throw e;
        }
    }

    /**
     * 跨设备封装（wrapFor）：派生 keyBizType@vinOrUid → encryptWith("dev-{recipientUid}", 派生密钥)
     */
    private ProvisioningResult doWrapFor(String recipientUid, String keyName, byte[] identity,
                                         BizType keyBizType, String deriveCtx) {
        String wrapKeyName = DEV_KEY_PREFIX + recipientUid;
        long startTime = System.currentTimeMillis();
        try {
            byte[] derived = kmsClient.hmac(keyName, identity);
            byte[] wrapped = kmsClient.encryptWith(wrapKeyName, derived);
            long duration = System.currentTimeMillis() - startTime;
            log.info("跨设备封装成功: keyBizType={}, keyName={}, wrapKey={}, {} (recipient={}), duration={}ms",
                    keyBizType.name(), keyName, wrapKeyName, deriveCtx, recipientUid, duration);
            cryptoMetrics.recordProvisioningWrap(duration);
            return buildWrapResult(wrapKeyName, derived, wrapped);
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("跨设备封装失败: keyBizType={}, keyName={}, wrapKey={}, {}", keyBizType.name(), keyName, wrapKeyName, deriveCtx, e);
            throw e;
        }
    }

    // ==================== 解封 ====================

    @Override
    public byte[] unwrapByVin(String vin, BizType bizType, byte[] wrapped) {
        validateProvisionCapability(bizType);
        Objects.requireNonNull(vin, "vin must not be null");
        Objects.requireNonNull(wrapped, "wrapped must not be null");
        String normalizedVin = normalizeVin(vin);
        String deviceSn = resolveDeviceSn(normalizedVin, bizType);
        return doUnwrap(deviceSn, bizType, wrapped, "vin=" + normalizedVin);
    }

    @Override
    public byte[] unwrapByUid(String uid, BizType bizType, byte[] wrapped) {
        validateProvisionCapability(bizType);
        Objects.requireNonNull(uid, "uid must not be null");
        Objects.requireNonNull(wrapped, "wrapped must not be null");
        String normalizedUid = normalizeUid(uid);
        return doUnwrap(normalizedUid, bizType, wrapped, "uid=" + normalizedUid);
    }

    private byte[] doUnwrap(String deviceSn, BizType bizType, byte[] wrapped, String logCtx) {
        String wrapKeyName = DEV_KEY_PREFIX + deviceSn;
        long startTime = System.currentTimeMillis();
        try {
            byte[] material = kmsClient.decryptWith(wrapKeyName, wrapped);
            long duration = System.currentTimeMillis() - startTime;
            log.info("解封成功: bizType={}, wrapKey={}, {} (sn={}), duration={}ms",
                    bizType.name(), wrapKeyName, logCtx, deviceSn, duration);
            cryptoMetrics.recordProvisioningUnwrap(duration);
            return material;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("解封失败: bizType={}, wrapKey={}, {}", bizType.name(), wrapKeyName, logCtx, e);
            throw e;
        }
    }

    // ==================== 内部方法 ====================

    /**
     * 解析 VIN→device_sn（经 DeviceResolver / VMD·TSP）
     * <p>
     * 用于 anchor=DEVICE 的派生与所有封装/解封（收方恒为器件）。
     * anchor=VEHICLE 的派生不调用此方法。
     */
    private String resolveDeviceSn(String vin, BizType bizType) {
        if (deviceResolver == null) {
            throw new CryptoDependencyUnavailableException(
                    "DeviceResolver unavailable, *ByVin methods require VMD/TSP binding. vin=" + vin);
        }
        return deviceResolver.resolveDeviceSn(vin, bizType);
    }

    /**
     * 构建派生结果（不封装，wrappedMaterial 为 null）
     */
    private ProvisioningResult buildDeriveResult(String keyName, String scope, String identity, byte[] derived) {
        ProvisioningResult result = new ProvisioningResult();
        result.setKmsKeyRef(buildKmsKeyRef(keyName, scope, identity));
        result.setKeySpec(KEY_SPEC);
        result.setProvider(provider);
        result.setAlgorithm(DERIVE_ALGORITHM);
        result.setKcv(computeKcv(derived));
        result.setWrappedMaterial(null);
        return result;
    }

    /**
     * 构建封装结果（by-reference：含密文，KCV 由派生密钥计算）
     */
    private ProvisioningResult buildWrapResult(String wrapKeyName, byte[] derived, byte[] wrapped) {
        ProvisioningResult result = new ProvisioningResult();
        result.setKmsKeyRef(wrapKeyName);
        result.setKeySpec(KEY_SPEC);
        result.setProvider(provider);
        result.setAlgorithm(WRAP_ALGORITHM);
        result.setKcv(computeKcv(derived));
        result.setWrappedMaterial(wrapped);
        return result;
    }

    /**
     * 构建唯一可定位的 KMS 密钥引用
     * <p>
     * 格式：{@code keyName:scope:identity}
     * （如 {@code secoc-master:vin:VIN12345} 或 {@code dev-root-master:sn:SN12345}），
     * 确保不同标识的派生结果在 VMD 等存储中可区分。
     */
    private String buildKmsKeyRef(String keyName, String scope, String identity) {
        return keyName + REF_SEPARATOR + scope + REF_SEPARATOR + identity;
    }

    /**
     * 计算密钥校验值 (Key Check Value)
     * <p>
     * 取派生结果或原始物料的前 {@value #KCV_LENGTH} 字节作为 KCV，
     * 用于在不暴露完整密钥的前提下校验密钥一致性。
     */
    private byte[] computeKcv(byte[] data) {
        return Arrays.copyOf(data, Math.min(KCV_LENGTH, data.length));
    }

    /**
     * 规范化 VIN：去首尾空白并转大写（ISO 3779 VIN 为大写字母 + 数字）
     */
    private String normalizeVin(String vin) {
        return vin.trim().toUpperCase();
    }

    /**
     * 规范化 UID：去首尾空白（uid 即 device_sn）
     */
    private String normalizeUid(String uid) {
        return uid.trim();
    }

    /**
     * 校验 bizType 支持派生/封装（prov != null），否则 fail-closed
     */
    private void validateProvisionCapability(BizType bizType) {
        Objects.requireNonNull(bizType, "bizType must not be null");
        if (!bizType.supportsProvision()) {
            throw new CryptoException(CryptoException.Reason.INVALID_BIZ_TYPE,
                    "Non-PROVISION bizType cannot be used for provisioning: " + bizType.name()) {};
        }
    }
}
