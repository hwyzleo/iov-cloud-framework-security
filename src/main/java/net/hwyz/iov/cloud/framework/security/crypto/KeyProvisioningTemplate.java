package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.ProvisioningResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;

/**
 * 通用密钥派生/封装下发门面 API 接口（FW-SEC-DSN-CR-013 §4.4/§7.2）。
 * <p>
 * 业务服务注入后直接调用，底层复用 {@code KmsClient} 通道原语。
 * 受 {@code crypto.provisioning.enabled} 条件装配，仅启用时才创建 Bean。
 * <p>
 * <strong>主入口 {@link #deriveAndWrap}</strong>：根派生型（{@code materialModel == DERIVED_ROOT}）在受控
 * Provider 边界内一次完成「根派生 + 证书公钥封装」，派生明文绝不返回 framework/VMD/VAGW/TSP/业务代码。
 * {@code bizType} 必传且须 {@code prov != null && materialModel == DERIVED_ROOT}，否则 fail-closed；
 * 派生公式、域隔离、KCV 与 Provider 路由由 framework 治理。
 * <p>
 * <strong>兼容门面（已废弃）</strong>：原 {@code deriveByVin/deriveByUid/wrapByVin/wrapByUid/wrapFor} 缺少
 * 派生所需的 purpose/operationId/幂等键，无法形成合法 {@code deriveAndWrap} 调用，默认 fail-closed，
 * 不提供任何隐式默认 purpose 或随机幂等键；{@code unwrapByVin/unwrapByUid} 仅在受控 legacy 对称 KEK
 * 场景（{@code crypto.provisioning.legacy-facade.enabled=true}）下保留旧行为。
 */
public interface KeyProvisioningTemplate {

    /**
     * 根派生并在受控边界内原子封装（FW-SEC-DSN-CR-013 §4.4/§7.2）。
     * <p>
     * 派生上下文固定包含协议标签、派生版本、规范化锚与 purpose；上/下行以 purpose 域隔离。
     * 同一锚点/purpose/根版本/派生版本代表同一逻辑密钥；更换收方证书只改变 Wrapped Key，
     * 不改变逻辑材料与 KCV。
     *
     * @param bizType        业务类型（须 {@code prov != null && materialModel == DERIVED_ROOT}）
     * @param anchor         派生锚点（规范化原文 + 摘要；锚类型须与 {@code prov.anchor} 一致）
     * @param purpose        受治理派生用途（UPLINK_AEAD / DOWNLINK_AEAD）
     * @param recipient      显式收方（首期 DEVICE_CERT_PUBLIC_KEY）
     * @param context        派生上下文（派生版本，首期 {@code v1}）
     * @param operationId    客户端生成的 UUIDv7 操作标识（对账主键）
     * @param idempotencyKey 幂等键
     * @param protocolRequestId    协议层请求标识（keyprov requestId；进入 AAD/HKDF canonical，
     *                             须与收方证书 enrollment requestId 区分，禁止传入证书申请编号）
     * @param protocolBusinessDomain 协议层业务域（如 V2C_COMM；区别于 KMS 材料 BizType.name()，
     *                             禁止传入 bizType.name()）
     * @return 瞬时派生封装结果（含 Wrapped Key 与非敏感元数据）
     */
    DerivedWrappedKey deriveAndWrap(BizType bizType, KeyAnchor anchor, KeyPurpose purpose,
                                    RecipientRef recipient, DerivationContext context,
                                    String operationId, String idempotencyKey,
                                    String protocolRequestId, String protocolBusinessDomain);

    /**
     * 派生（按 VIN）
     *
     * @deprecated 由 FW-SEC-DSN-CR-013 取代：根派生主入口为 {@link #deriveAndWrap}。
     * 本方法缺少 purpose/operationId/幂等键，无法形成合法派生调用，默认 fail-closed。
     */
    @Deprecated
    ProvisioningResult deriveByVin(String vin, BizType bizType);

    /**
     * 派生（按 uid，仅 {@code anchor=DEVICE}）
     *
     * @deprecated 由 FW-SEC-DSN-CR-013 取代：请使用 {@link #deriveAndWrap}。默认 fail-closed。
     */
    @Deprecated
    ProvisioningResult deriveByUid(String uid, BizType bizType);

    /**
     * 封装下发（按 VIN 寻址 device_sn，by-reference）
     *
     * @deprecated 由 FW-SEC-DSN-CR-013 取代：请使用 {@link #deriveAndWrap}。默认 fail-closed。
     */
    @Deprecated
    ProvisioningResult wrapByVin(String vin, BizType bizType);

    /**
     * 封装下发（uid 即 device_sn，by-reference）
     *
     * @deprecated 由 FW-SEC-DSN-CR-013 取代：请使用 {@link #deriveAndWrap}。默认 fail-closed。
     */
    @Deprecated
    ProvisioningResult wrapByUid(String uid, BizType bizType);

    /**
     * 跨设备封装下发（by-reference，CR-004）
     *
     * @deprecated 由 FW-SEC-DSN-CR-013 取代：请使用 {@link #deriveAndWrap}。默认 fail-closed。
     */
    @Deprecated
    ProvisioningResult wrapFor(BizType keyBizType, String vinOrUid, String recipientUid);

    /**
     * 解封密钥物料（按 VIN 寻址 device_sn）
     * <p>
     * 仅在受控 legacy 对称 KEK 场景（{@code crypto.provisioning.legacy-facade.enabled=true}）下保留；
     * 否则 fail-closed。根派生型（{@code DERIVED_ROOT}）不使用云端解封，非对称账本不适用。
     *
     * @param vin     VIN
     * @param bizType 业务类型
     * @param wrapped 密文
     * @return 明文物料
     * @deprecated 由 FW-SEC-DSN-CR-013 取代：根派生型不再走云端对称解封，默认 fail-closed。
     */
    @Deprecated
    byte[] unwrapByVin(String vin, BizType bizType, byte[] wrapped);

    /**
     * 解封密钥物料（uid 即 device_sn）
     * <p>
     * 仅在受控 legacy 对称 KEK 场景（{@code crypto.provisioning.legacy-facade.enabled=true}）下保留；
     * 否则 fail-closed。
     *
     * @param uid     器件唯一标识（即 device_sn）
     * @param bizType 业务类型
     * @param wrapped 密文
     * @return 明文物料
     * @deprecated 由 FW-SEC-DSN-CR-013 取代：根派生型不再走云端对称解封，默认 fail-closed。
     */
    @Deprecated
    byte[] unwrapByUid(String uid, BizType bizType, byte[] wrapped);
}
