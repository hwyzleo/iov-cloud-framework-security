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
    DERIVED_KEY_FORMAT_INVALID("DERIVED_KEY_FORMAT_INVALID", false),

    /**
     * 新 V2C ECDH-ES keyprov 未配置 aadProfileId（FW-SEC-DSN-CR-020 §6 收紧）：
     * 不得为新的 V2C operation 静默生成旧 core AAD 信封。
     */
    AAD_PROFILE_NOT_CONFIGURED("AAD_PROFILE_NOT_CONFIGURED", false),

    /**
     * 配置的 aadProfileId 未在受控 registry 注册（FW-SEC-DSN-CR-020 §2）：
     * 不得回退旧 FW AAD 或空 AAD；启动/readiness 必须失败。
     */
    AAD_PROFILE_UNAVAILABLE("AAD_PROFILE_UNAVAILABLE", false),

    /**
     * AAD encoder 输出非法（非确定/超限/抛错，FW-SEC-DSN-CR-020 §7 测试 3）。
     */
    AAD_ENCODER_OUTPUT_INVALID("AAD_ENCODER_OUTPUT_INVALID", false),

    /**
     * Operation Result Store 不可用（读写/对账失败）：capability DOWN，
     * 不得退回重新生成新信封（FW-SEC-DSN-CR-014 §6；CR-020 §4）。
     */
    RESULT_STORE_UNAVAILABLE("RESULT_STORE_UNAVAILABLE", true);

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
