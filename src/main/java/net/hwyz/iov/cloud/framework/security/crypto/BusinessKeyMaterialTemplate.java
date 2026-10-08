package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyCreateRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyMetadata;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.BusinessKeyRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RevocationRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RevocationResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrappedBusinessKey;

/**
 * 运行期业务密钥密码学材料门面（FW-SEC-DSN-CR-009 §3）。
 * <p>
 * 受 {@code crypto.business-key.enabled} 条件装配。仅对<strong>显式 {@link BusinessKeyRef}</strong>
 * 执行 create / wrap / getMetadata / revoke；不提供按 deviceSn 选 active key 的方法（RD-009-2）。
 * <p>
 * 职责边界：
 * <ul>
 *   <li>VMD：设备绑定、业务域/用途授权、ACTIVE 切换、businessKeyVersion 与业务状态</li>
 *   <li>framework-security：KMS 通道、创建材料、按显式引用封装/取用、吊销、类型化异常、缓存</li>
 *   <li>KMS/HSM：密钥材料、kmsKeyRef/kmsKeyVersion、密码学状态与原语</li>
 * </ul>
 */
public interface BusinessKeyMaterialTemplate {

    /**
     * 创建业务密钥材料（不决定业务 ACTIVE）。
     * <p>
     * 不接收 VIN、deviceSn、businessDomain、purpose 或 businessKeyVersion；
     * 创建结果未知时抛 {@link net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException}，
     * 调用方须使用原幂等键对账。
     *
     * @param request 创建请求
     * @return 材料创建结果（含 keyId/kmsKeyRef/kmsKeyVersion/metadata）
     */
    BusinessKeyMaterial create(BusinessKeyCreateRequest request);

    /**
     * 按显式 keyRef 向显式收方封装（无隐式收方推断）。
     * <p>
     * 返回的 Wrapped Key 使用后即释放，不写入 framework 结果存储、日志或事件。
     * {@link net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode#DEVICE_ROOT_KEK}
     * 仅在显式提供可信 wrappingKeyRef 时可用，不得从 deviceSn 猜测。
     *
     * @param keyRef    显式业务密钥引用
     * @param recipient 显式收方引用
     * @param context   封装上下文
     * @return 瞬时封装结果
     */
    WrappedBusinessKey wrap(BusinessKeyRef keyRef, RecipientRef recipient, WrapContext context);

    /**
     * 查询显式 keyRef 的材料元数据。
     *
     * @param keyRef 显式业务密钥引用
     * @return 材料元数据（含密码学状态）
     */
    BusinessKeyMetadata getMetadata(BusinessKeyRef keyRef);

    /**
     * 按显式 keyRef 吊销（幂等）。
     * <p>
     * 结果成功返回 KMS 密码学状态；结果未知抛
     * {@link net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoOperationOutcomeUnknownException}，
     * framework 不得在超时后自动把密钥标记为可用。
     *
     * @param keyRef  显式业务密钥引用
     * @param request 吊销请求
     * @return 吊销结果（密码学状态）
     */
    RevocationResult revoke(BusinessKeyRef keyRef, RevocationRequest request);
}
