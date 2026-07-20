package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.util.Objects;

/**
 * 证书配置文件（受治理枚举）
 * <p>
 * 映射 PKI profile 标识及允许的主体类型、算法与用途。
 * 新增或修改 profile 走 CR + framework 发版，业务方不得传任意字符串绕过治理。
 */
public record CertificateProfile(

        /**
         * profile 名称（framework 内部标识）
         */
        String name,

        /**
         * PKI profile 标识
         */
        String pkiProfileId,

        /**
         * 允许的主体类型
         */
        SubjectType subjectType,

        /**
         * 允许的算法
         */
        String allowedAlgorithm,

        /**
         * 用途描述
         */
        String usage
) {

    public enum SubjectType {
        /**
         * 服务 mTLS
         */
        SERVICE,
        /**
         * 业务签名
         */
        BUSINESS_SIGNATURE,
        /**
         * 设备身份证书
         */
        DEVICE_IDENTITY,
        /**
         * 用户身份证书
         */
        USER_IDENTITY
    }

    public CertificateProfile {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(pkiProfileId, "pkiProfileId must not be null");
        Objects.requireNonNull(subjectType, "subjectType must not be null");
    }
}
