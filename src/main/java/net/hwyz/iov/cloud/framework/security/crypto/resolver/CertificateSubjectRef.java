package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import java.io.Serializable;
import java.util.Objects;

/**
 * 安全关键证书主体引用（FW-SEC-REQ/DSN-CR-012 §4.2）。
 * <p>
 * 主体用于领域目录把「主体 → certSerial/requestId/provider locator」映射，属安全决策输入，
 * 因此必须是显式强类型字段，<b>不得</b>塞入自由 {@code context}（context 仅承载不参与安全决策的扩展信息）。
 * <ul>
 *   <li>{@link Type#VEHICLE}：车辆级主体（VIN）</li>
 *   <li>{@link Type#DEVICE}：设备级主体（deviceSn / 器件标识）</li>
 *   <li>{@link Type#USER}：用户级主体（uid）</li>
 * </ul>
 */
public record CertificateSubjectRef(Type type, String value) implements Serializable {

    public enum Type {
        VEHICLE,
        DEVICE,
        USER
    }

    public CertificateSubjectRef {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(value, "value must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException("subject value must not be blank");
        }
    }

    public static CertificateSubjectRef ofVehicle(String vin) {
        return new CertificateSubjectRef(Type.VEHICLE, vin);
    }

    public static CertificateSubjectRef ofDevice(String deviceSn) {
        return new CertificateSubjectRef(Type.DEVICE, deviceSn);
    }

    public static CertificateSubjectRef ofUser(String uid) {
        return new CertificateSubjectRef(Type.USER, uid);
    }
}
