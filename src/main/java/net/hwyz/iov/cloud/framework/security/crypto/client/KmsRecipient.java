package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;

import java.util.Objects;

/**
 * KMS 收方（封装目标，FW-SEC-DSN-CR-009 §9）。
 * <p>
 * 由 {@code RecipientRef} 映射而来；收方与封装模式一一对应，无隐式推断。
 *
 * @param mode           封装模式
 * @param certSerial     设备证书序列号（DEVICE_CERT_PUBLIC_KEY / DeviceCertificate）
 * @param spki           收方公钥 SPKI（DEVICE_CERT_PUBLIC_KEY / PublicKey）
 * @param audience       运行期身份（RUNTIME）
 * @param wrappingKeyRef 可信根 KEK 引用（DEVICE_ROOT_KEK）
 */
public record KmsRecipient(
        WrapMode mode,
        String certSerial,
        byte[] spki,
        String audience,
        String wrappingKeyRef) {

    public KmsRecipient {
        Objects.requireNonNull(mode, "mode must not be null");
    }

    public static KmsRecipient deviceCertificate(String certSerial) {
        return new KmsRecipient(WrapMode.DEVICE_CERT_PUBLIC_KEY, certSerial, null, null, null);
    }

    public static KmsRecipient publicKey(byte[] spki) {
        return new KmsRecipient(WrapMode.DEVICE_CERT_PUBLIC_KEY, null, spki, null, null);
    }

    public static KmsRecipient runtime(String audience) {
        return new KmsRecipient(WrapMode.RUNTIME, null, null, audience, null);
    }

    public static KmsRecipient deviceRoot(String wrappingKeyRef) {
        return new KmsRecipient(WrapMode.DEVICE_ROOT_KEK, null, null, null, wrappingKeyRef);
    }
}
