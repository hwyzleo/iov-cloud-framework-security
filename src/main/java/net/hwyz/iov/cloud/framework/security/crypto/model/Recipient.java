package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Objects;

/**
 * 证书加密收方作用域（标识「加密给谁」= 收方）
 * <p>
 * 与签名侧 {@link KeyScope} 语义相反：{@code KeyScope} 选我方 KMS 私钥；
 * {@code Recipient} 选对方（收方）的公钥/证书，不经 {@code BizType}、不涉 KMS 私钥。
 * <p>
 * 调用方若已持证书/公钥就用 {@link #ofCert} / {@link #ofPublicKey} 直接加密；
 * 若只知主体（VIN/device/UID/certSerial），由 {@code CertResolver} SPI 解析出收方证书。
 */
public sealed interface Recipient permits
        Recipient.CertRecipient, Recipient.PublicKeyRecipient, Recipient.SubjectRecipient {

    /**
     * 主体引用类型
     */
    enum SubjectType {
        VIN,
        DEVICE,
        USER,
        SERIAL
    }

    /**
     * 直接给收方证书 DER
     */
    static Recipient ofCert(byte[] certDer) {
        return new CertRecipient(certDer);
    }

    /**
     * 直接给收方公钥 SPKI DER
     */
    static Recipient ofPublicKey(byte[] spki) {
        return new PublicKeyRecipient(spki);
    }

    /**
     * 按 VIN 引用收方（由 CertResolver 解析）
     */
    static Recipient ofVehicle(String vin) {
        return new SubjectRecipient(SubjectType.VIN, vin);
    }

    /**
     * 按设备 SN 引用收方（由 CertResolver 解析）
     */
    static Recipient ofDevice(String deviceSn) {
        return new SubjectRecipient(SubjectType.DEVICE, deviceSn);
    }

    /**
     * 按 UID 引用收方（由 CertResolver 解析）
     */
    static Recipient ofUser(String uid) {
        return new SubjectRecipient(SubjectType.USER, uid);
    }

    /**
     * 按证书序列号引用收方（由 CertResolver 解析）
     */
    static Recipient ofSerial(String certSerial) {
        return new SubjectRecipient(SubjectType.SERIAL, certSerial);
    }

    /**
     * 直接持有证书 DER 的收方
     */
    record CertRecipient(byte[] certDer) implements Recipient {
        public CertRecipient {
            Objects.requireNonNull(certDer, "certDer must not be null");
        }
    }

    /**
     * 直接持有公钥 SPKI DER 的收方
     */
    record PublicKeyRecipient(byte[] spki) implements Recipient {
        public PublicKeyRecipient {
            Objects.requireNonNull(spki, "spki must not be null");
        }
    }

    /**
     * 按主体引用的收方（需 CertResolver 解析为证书/公钥）
     *
     * @param type  主体类型
     * @param value 主体值
     */
    record SubjectRecipient(SubjectType type, String value) implements Recipient {
        public SubjectRecipient {
            Objects.requireNonNull(type, "type must not be null");
            Objects.requireNonNull(value, "value must not be null");
        }
    }
}
