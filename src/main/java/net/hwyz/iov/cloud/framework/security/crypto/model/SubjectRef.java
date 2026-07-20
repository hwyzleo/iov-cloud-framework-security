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
