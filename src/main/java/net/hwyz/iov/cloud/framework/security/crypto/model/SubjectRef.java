package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Objects;

/**
 * 主体引用
 *
 * @param type  主体类型
 * @param value 主体值
 */
public record SubjectRef(

        SubjectType type,

        String value
) {

    public enum SubjectType {
        /**
         * 通用名称
         */
        CN,
        /**
         * 组织单位
         */
        OU,
        /**
         * 组织
         */
        O,
        /**
         * 设备序列号
         */
        DEVICE_SN,
        /**
         * 设备安全芯片 UID（hsm_uid / ecu_uid，证书主体身份，VMD-DSN-CR-054）
         */
        DEVICE_UID,
        /**
         * 车辆识别号
         */
        VIN,
        /**
         * 用户 ID
         */
        UID
    }

    public SubjectRef {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(value, "value must not be null");
    }
}
