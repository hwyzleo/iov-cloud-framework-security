package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

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
     * 按设备证书取收方证书公钥封装（首期 keyprov 模式）。
     * <p>
     * 向后兼容仅传 {@code certSerial}；也可携带 {@code requestId}、leaf DER、SPKI、
     * SHA-256 fingerprint 与必要上下文（FW-SEC-DSN-CR-012 §4.3）。
     * fingerprint 仅用于固定/比对，不能单独替代 Wrap 所需的 DER/SPKI。
     *
     * @param certSerial        证书序列号（可空，向后兼容）
     * @param requestId         证书注册 requestId（可空）
     * @param certificateDer    叶子证书 DER（可空）
     * @param spki              收方公钥 SPKI DER（可空）
     * @param sha256Fingerprint 期望 SHA-256 指纹（可空）
     * @param context           非安全扩展上下文（可空）
     */
    record DeviceCertificate(String certSerial, String requestId, byte[] certificateDer, byte[] spki,
                             String sha256Fingerprint, Map<String, String> context) implements RecipientRef {

        public DeviceCertificate {
            certificateDer = certificateDer == null ? null : certificateDer.clone();
            spki = spki == null ? null : spki.clone();
            context = context == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(context));
        }

        /**
         * 向后兼容构造：仅传序列号。
         */
        public DeviceCertificate(String certSerial) {
            this(certSerial, null, null, null, null, null);
        }

        public static DeviceCertificate ofCertificate(byte[] certificateDer) {
            return new DeviceCertificate(null, null, certificateDer, null, null, null);
        }

        public static DeviceCertificate ofSpki(byte[] spki) {
            return new DeviceCertificate(null, null, null, spki, null, null);
        }

        public static DeviceCertificate ofRequestId(String requestId) {
            return new DeviceCertificate(null, requestId, null, null, null, null);
        }
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
