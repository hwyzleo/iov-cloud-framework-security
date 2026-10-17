package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.WrapMode;

import java.util.List;
import java.util.Objects;

/**
 * KMS 收方（封装目标，FW-SEC-DSN-CR-009 §9；FW-SEC-DSN-CR-011 §6.2）。
 * <p>
 * 由 {@code RecipientRef} 映射而来；收方与封装模式一一对应，无隐式推断。
 * <ul>
 *   <li>DEVICE_CERT_PUBLIC_KEY：受信证书 DER/SPKI + SHA-256 fingerprint + 允许算法</li>
 *   <li>RUNTIME：登记的 audience / runtimeKeyRef</li>
 *   <li>DEVICE_ROOT_KEK：显式可信 wrappingKeyRef</li>
 * </ul>
 *
 * @param mode                         封装模式
 * @param certSerial                   设备证书序列号（DEVICE_CERT_PUBLIC_KEY / DeviceCertificate）
 * @param certificateDer               受信证书 DER（Provider 再校验算法与指纹）
 * @param certificateSha256Fingerprint 证书 SHA-256 指纹（十六进制小写）
 * @param spki                         收方公钥 SPKI（PublicKey）
 * @param allowedAlgorithms            允许的封装算法（可空表示由 Provider 策略决定）
 * @param audience                     运行期身份（RUNTIME）
 * @param runtimeKeyRef                运行期 KEK 引用（RUNTIME，可空）
 * @param wrappingKeyRef               可信根 KEK 引用（DEVICE_ROOT_KEK）
 */
public record KmsRecipient(
        WrapMode mode,
        String certSerial,
        byte[] certificateDer,
        String certificateSha256Fingerprint,
        byte[] spki,
        List<String> allowedAlgorithms,
        String audience,
        String runtimeKeyRef,
        String wrappingKeyRef) {

    public KmsRecipient {
        Objects.requireNonNull(mode, "mode must not be null");
        allowedAlgorithms = allowedAlgorithms == null ? null : List.copyOf(allowedAlgorithms);
    }

    /**
     * 设备证书公钥封装（仅序列号；Provider 侧按证书目录解析，兼容旧口径）。
     */
    public static KmsRecipient deviceCertificate(String certSerial) {
        return new KmsRecipient(WrapMode.DEVICE_CERT_PUBLIC_KEY, certSerial,
                null, null, null, null, null, null, null);
    }

    /**
     * 设备证书公钥封装：framework 先经证书解析组件取得受信证书 DER 并计算指纹（RD-011-7）。
     */
    public static KmsRecipient deviceCertificate(String certSerial, byte[] certificateDer,
                                                 String certificateSha256Fingerprint,
                                                 byte[] spki, List<String> allowedAlgorithms) {
        return new KmsRecipient(WrapMode.DEVICE_CERT_PUBLIC_KEY, certSerial,
                certificateDer, certificateSha256Fingerprint, spki, allowedAlgorithms,
                null, null, null);
    }

    /**
     * 直接按收方公钥 SPKI 封装。
     */
    public static KmsRecipient publicKey(byte[] spki) {
        return new KmsRecipient(WrapMode.DEVICE_CERT_PUBLIC_KEY, null,
                null, null, spki, null, null, null, null);
    }

    public static KmsRecipient runtime(String audience) {
        return new KmsRecipient(WrapMode.RUNTIME, null, null, null, null, null,
                audience, null, null);
    }

    public static KmsRecipient deviceRoot(String wrappingKeyRef) {
        return new KmsRecipient(WrapMode.DEVICE_ROOT_KEK, null, null, null, null, null,
                null, null, wrappingKeyRef);
    }
}
