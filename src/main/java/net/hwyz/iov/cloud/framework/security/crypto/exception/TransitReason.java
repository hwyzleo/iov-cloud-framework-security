package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * Transit 派生/封装稳定失败原因（FW-SEC-DSN-CR-019 §10）。
 * <p>
 * VMD keyprov 依赖本枚举的稳定 {@code wireName} 判断 capability/请求失败类别，
 * <strong>不解析异常正文</strong>。取值一经发布即冻结，新增取值走 CR + framework 发版。
 */
public enum TransitReason {

    /**
     * Transit/OpenBao 不可达或超预算（连接失败、5xx、总预算超限）。
     */
    TRANSIT_UNAVAILABLE("TRANSIT_UNAVAILABLE", true),

    /**
     * OpenBao sealed 或未初始化，无法派生。
     */
    TRANSIT_SEALED("TRANSIT_SEALED", true),

    /**
     * AppRole 认证失败（重新认证一次后仍 401/403）。
     */
    TRANSIT_AUTH_FAILED("TRANSIT_AUTH_FAILED", false),

    /**
     * 根密钥不存在（transit/keys/&lt;root&gt; 404）。
     */
    TRANSIT_ROOT_NOT_FOUND("TRANSIT_ROOT_NOT_FOUND", false),

    /**
     * 根密钥类型/配置与策略不符（类型、derived、exportable 等）。
     */
    TRANSIT_ROOT_TYPE_MISMATCH("TRANSIT_ROOT_TYPE_MISMATCH", false),

    /**
     * HMAC 路径权限不足（403）。
     */
    TRANSIT_HMAC_FORBIDDEN("TRANSIT_HMAC_FORBIDDEN", false),

    /**
     * BizType 策略非法：未登记、purpose/派生版本/WrapMode 不允许或请求覆盖根名/算法。
     */
    DERIVATION_POLICY_INVALID("DERIVATION_POLICY_INVALID", false),

    /**
     * 收方证书最终密码学门禁失败（证据缺失/过期/指纹与套件不一致等）。
     */
    RECIPIENT_CERTIFICATE_INVALID("RECIPIENT_CERTIFICATE_INVALID", false),

    /**
     * 本地 Wrap 算法/JCA Provider/SecureRandom 不可用或套件不允许。
     */
    WRAP_ALGORITHM_UNAVAILABLE("WRAP_ALGORITHM_UNAVAILABLE", false),

    /**
     * Transit 返回的派生材料长度非法（V2C 首期必须 32 字节）。
     */
    DERIVED_KEY_LENGTH_INVALID("DERIVED_KEY_LENGTH_INVALID", false),

    /**
     * Transit HMAC 响应格式非法（版本前缀未知、Base64 非法）。
     */
    DERIVED_KEY_FORMAT_INVALID("DERIVED_KEY_FORMAT_INVALID", false);

    private final String wireName;
    private final boolean retryable;

    TransitReason(String wireName, boolean retryable) {
        this.wireName = wireName;
        this.retryable = retryable;
    }

    /**
     * 稳定 wire 名称（VMD 依赖，不随异常正文变化）。
     */
    public String wireName() {
        return wireName;
    }

    /**
     * 是否可按预算重试（瞬时依赖失败）；策略/证书/格式类确定性失败为 false。
     */
    public boolean isRetryable() {
        return retryable;
    }
}
