package net.hwyz.iov.cloud.framework.security.crypto.model.businesskey;

import java.io.Serializable;

/**
 * 调用方身份（FW-SEC-DSN-CR-009 §4，目录授权入参）。
 * <p>
 * 调用方授权由 VMD 目录权威判定，framework 不重复解释。
 *
 * @param principal 主体标识
 * @param source    来源（服务/会话，可为 null）
 */
public record CallerIdentity(String principal, String source) implements Serializable {

    public static CallerIdentity anonymous() {
        return new CallerIdentity("anonymous", null);
    }
}
