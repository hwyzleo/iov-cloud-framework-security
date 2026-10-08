package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;

/**
 * 收方引用（FW-SEC-DSN-CR-009 §3）。
 * <p>
 * 封装必须接收显式 {@link RecipientRef}，无隐式收方推断（RD-009-2）。
 * <ul>
 *   <li>{@link DeviceCertificate}：按设备证书序列号取收方证书公钥封装 → {@link WrapMode#DEVICE_CERT_PUBLIC_KEY}</li>
 *   <li>{@link PublicKey}：直接使用收方公钥 SPKI 封装 → {@link WrapMode#DEVICE_CERT_PUBLIC_KEY}</li>
 *   <li>{@link RuntimeIdentity}：向运行期身份封装（缓存取钥）→ {@link WrapMode#RUNTIME}</li>
 *   <li>{@link DeviceRoot}：使用显式可信 wrappingKeyRef 的根 KEK 封装 → {@link WrapMode#DEVICE_ROOT_KEK}</li>
 * </ul>
 */
public sealed interface RecipientRef extends Serializable {

    /**
     * 按设备证书序列号取收方证书公钥封装（首期 keyprov 模式）。
     *
     * @param certSerial 设备证书序列号
     */
    record DeviceCertificate(String certSerial) implements RecipientRef {
    }

    /**
     * 直接按收方公钥 SPKI 封装。
     *
     * @param spki 收方公钥 SPKI DER
     */
    record PublicKey(byte[] spki) implements RecipientRef {
    }

    /**
     * 向运行期身份封装（运行期缓存取钥场景）。
     *
     * @param audience 运行期身份标识（受控运行时边界）
     */
    record RuntimeIdentity(String audience) implements RecipientRef {
    }

    /**
     * 使用显式可信 wrappingKeyRef 的根 KEK 封装。
     * <p>
     * 仅当显式提供可信 wrappingKeyRef 时可用，不得从 deviceSn 猜测（RD-009-3）。
     *
     * @param wrappingKeyRef 可信根 KEK 的 KMS 引用
     */
    record DeviceRoot(String wrappingKeyRef) implements RecipientRef {
    }

    /**
     * 由收方类型推导封装模式；与 {@link WrapContext#mode()} 不一致时 fail-closed。
     *
     * @return WrapMode
     */
    default WrapMode wrapMode() {
        if (this instanceof DeviceCertificate) {
            return WrapMode.DEVICE_CERT_PUBLIC_KEY;
        }
        if (this instanceof PublicKey) {
            return WrapMode.DEVICE_CERT_PUBLIC_KEY;
        }
        if (this instanceof RuntimeIdentity) {
            return WrapMode.RUNTIME;
        }
        if (this instanceof DeviceRoot) {
            return WrapMode.DEVICE_ROOT_KEK;
        }
        throw new IllegalStateException("未知收方类型: " + getClass().getName());
    }
}
