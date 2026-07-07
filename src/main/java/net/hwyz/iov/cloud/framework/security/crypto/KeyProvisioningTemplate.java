package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.ProvisioningResult;

/**
 * 通用密钥派生/封装下发门面 API 接口
 * <p>
 * 业务服务注入后直接调用，底层复用 {@code KmsClient} 通道原语。
 * 受 {@code crypto.provisioning.enabled} 条件装配，仅启用时才创建 Bean。
 * <p>
 * <strong>两个正交的轴</strong>：
 * <ol>
 *   <li><strong>锚定层级</strong>（秘密绑谁）由 {@code bizType.prov.anchor(VEHICLE/DEVICE)} 决定，业务无感；
 *   <li><strong>方法后缀 ByVin/ByUid</strong> 只表示调用方手里有哪个标识——VIN 优先
 *       （多数业务只关心 VIN、只传 {@code (vin, bizType)}），{@code ByUid} 仅用于
 *       VIN 尚未产生的早期预置/直指芯片。
 * </ol>
 * <p>
 * <strong>派生取值按 anchor 决定</strong>：
 * <ul>
 *   <li>{@code anchor=VEHICLE}（车级）→ {@code HMAC(keyName, VIN)}，<strong>不解析设备</strong>
 *       （换 TBOX 不变），只能用 {@code deriveByVin}；{@code deriveByUid} 传 VEHICLE 项 fail-closed；</li>
 *   <li>{@code anchor=DEVICE}（设备级）→ {@code deriveByVin} 先 VIN→device_sn 解析再 HMAC，
 *       {@code deriveByUid} 直接 {@code HMAC(keyName, uid)}，两路指向同一芯片、同一秘密。</li>
 * </ul>
 * <strong>封装/解封</strong>收方恒为器件：{@code *ByVin} 先解析设备、{@code *ByUid} 直指 {@code dev-{uid}}。
 * <p>
 * {@code bizType} 必传且须 {@code prov != null}（声明支持 PROVISION，携带 keyName + anchor），
 * 否则 fail-closed。派生公式与 KCV 由框架拥有，业务方不自算。
 */
public interface KeyProvisioningTemplate {

    /**
     * 派生（按 VIN）
     * <p>
     * {@code anchor=VEHICLE}：{@code HMAC(keyName, VIN)}，不解析设备（换件不变、D16 预置可用）；<br>
     * {@code anchor=DEVICE}：先 VIN→device_sn 解析，再 {@code HMAC(keyName, device_sn)}。
     * 与 {@link #deriveByUid} 对同一芯片产出同一秘密。
     *
     * @param vin     VIN
     * @param bizType 业务类型（prov 必须非空）
     * @return 派生结果（不含封装密文）
     */
    ProvisioningResult deriveByVin(String vin, BizType bizType);

    /**
     * 派生（按 uid，仅 {@code anchor=DEVICE}）
     * <p>
     * 直接 {@code HMAC(keyName, uid)}，与 {@link #deriveByVin} 对同一芯片产出同一秘密。
     * 传 {@code anchor=VEHICLE} 项 fail-closed。
     *
     * @param uid     器件唯一标识（即 device_sn）
     * @param bizType 业务类型（prov 必须非空，且 anchor=DEVICE）
     * @return 派生结果（不含封装密文）
     */
    ProvisioningResult deriveByUid(String uid, BizType bizType);

    /**
     * 封装密钥物料下发（按 VIN 寻址 device_sn）
     * <p>
     * 先 VIN→device_sn 解析，再 {@code encryptWith("dev-{sn}", material)}。
     * 封装收方恒为器件，与 anchor 无关。
     *
     * @param vin      VIN
     * @param bizType  业务类型（prov 必须非空）
     * @param material 待封装物料
     * @return 封装结果（含密文）
     */
    ProvisioningResult wrapByVin(String vin, BizType bizType, byte[] material);

    /**
     * 封装密钥物料下发（uid 即 device_sn）
     * <p>
     * 直接 {@code encryptWith("dev-{uid}", material)}，用于 VIN 未绑定/预置阶段。
     *
     * @param uid      器件唯一标识（即 device_sn）
     * @param bizType  业务类型（prov 必须非空）
     * @param material 待封装物料
     * @return 封装结果（含密文）
     */
    ProvisioningResult wrapByUid(String uid, BizType bizType, byte[] material);

    /**
     * 解封密钥物料（按 VIN 寻址 device_sn）
     * <p>
     * 先 VIN→device_sn 解析，再 {@code decryptWith("dev-{sn}", wrapped)}。
     *
     * @param vin      VIN
     * @param bizType  业务类型（prov 必须非空）
     * @param wrapped  密文
     * @return 明文物料
     */
    byte[] unwrapByVin(String vin, BizType bizType, byte[] wrapped);

    /**
     * 解封密钥物料（uid 即 device_sn）
     * <p>
     * 直接 {@code decryptWith("dev-{uid}", wrapped)}。
     *
     * @param uid      器件唯一标识（即 device_sn）
     * @param bizType  业务类型（prov 必须非空）
     * @param wrapped  密文
     * @return 明文物料
     */
    byte[] unwrapByUid(String uid, BizType bizType, byte[] wrapped);
}
