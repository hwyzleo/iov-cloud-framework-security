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
 * <p>
 * <strong>封装/解封（by-reference，CR-004）</strong>：封装方法不传明文 material——KMS 内部按
 * {@code bizType.prov.keyName} 派生密钥后 {@code encryptWith("dev-{sn|uid}", 派生密钥)}（内建
 * derive-and-wrap，明文不出 KMS）。封装收方恒为器件：{@code *ByVin} 先解析设备、{@code *ByUid}
 * 直指 {@code dev-{uid}}。{@code wrapByUid} 仅接受 {@code anchor=DEVICE}（VEHICLE 派生需 VIN，
 * 无 VIN 时 fail-closed）。
 * <p>
 * <strong>跨设备封装 {@code wrapFor}</strong>：仅 VEHICLE 锚定且收方≠VIN 默认器件时用
 * （如防盗组密钥→安全灌注机 KLD）；DEVICE 锚定自交付用 {@code wrapByUid}/{@code wrapByVin} 即可。
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
     * 封装下发（按 VIN 寻址 device_sn，by-reference）
     * <p>
     * KMS 内部按 {@code bizType.prov.keyName} 派生密钥后 {@code encryptWith("dev-{sn}", 派生密钥)}，
     * 明文不出 KMS。派生取值按 anchor 决定（VEHICLE→HMAC(keyName, VIN)；DEVICE→HMAC(keyName, device_sn)），
     * 封装收方恒为器件（解析 device_sn 后以 {@code dev-{sn}} 封装）。
     *
     * @param vin     VIN
     * @param bizType 业务类型（prov 必须非空）
     * @return 封装结果（含密文）
     */
    ProvisioningResult wrapByVin(String vin, BizType bizType);

    /**
     * 封装下发（uid 即 device_sn，by-reference）
     * <p>
     * KMS 内部 {@code hmac(keyName, uid)} 派生 → {@code encryptWith("dev-{uid}", 派生密钥)}，
     * 用于 VIN 未绑定/预置阶段。仅接受 {@code anchor=DEVICE}；VEHICLE 派生需 VIN，传 VEHICLE 项 fail-closed。
     *
     * @param uid     器件唯一标识（即 device_sn）
     * @param bizType 业务类型（prov 必须非空，且 anchor=DEVICE）
     * @return 封装结果（含密文）
     */
    ProvisioningResult wrapByUid(String uid, BizType bizType);

    /**
     * 跨设备封装下发（by-reference，CR-004）
     * <p>
     * ① {@code keyBizType + vinOrUid} 决定<strong>派生哪把密钥</strong>；
     * ② {@code recipientUid} 决定<strong>封装给谁</strong>（{@code dev-{recipientUid}}）。
     * <p>
     * 适用边界：仅 VEHICLE 锚定且收方≠VIN 默认器件时用（如防盗组密钥→安全灌注机 KLD）；
     * DEVICE 锚定自交付用 {@link #wrapByUid}/{@link #wrapByVin} 即可。
     * <p>
     * 派生取值：VEHICLE→{@code hmac(keyName, vinOrUid)}（vinOrUid 即 VIN）；
     * DEVICE→{@code hmac(keyName, vinOrUid)}（vinOrUid 即 uid）。
     *
     * @param keyBizType  决定派生哪把密钥的业务类型（prov 必须非空）
     * @param vinOrUid    VIN（VEHICLE 锚定）或 uid（DEVICE 锚定）
     * @param recipientUid 收方器件 uid
     * @return 封装结果（含密文）
     */
    ProvisioningResult wrapFor(BizType keyBizType, String vinOrUid, String recipientUid);

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
