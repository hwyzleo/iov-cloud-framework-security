package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * PKI 证书状态/吊销查询配置（FW-SEC-DSN-CR-010 §5）
 * <p>
 * 前缀 {@code crypto.pki.revocation}。默认 {@code enabled=false}，避免升级 framework 后改变既有应用行为。
 * 不新增 {@code pki.service.*} 别名；不兼容读取消费方私造键。
 * <p>
 * 与 {@code crypto.pki.connect-timeout/read-timeout} 的关系：逐次请求的 connect/read 超时沿用
 * {@code crypto.pki.*}；本能力另有 {@code total-timeout} 总预算，所有协议尝试与重试共享。
 */
@Configuration
@RefreshScope
@ConfigurationProperties(prefix = "crypto.pki.revocation")
public class PkiRevocationProperties {

    /**
     * 是否启用证书状态查询能力（默认关闭）
     */
    private boolean enabled = false;

    /**
     * 协议模式：ocsp | crl | ocsp-then-crl
     */
    private String mode = "ocsp-then-crl";

    /**
     * 单次查询总预算，所有协议尝试与重试共享
     */
    private Duration totalTimeout = Duration.ofSeconds(1);

    /**
     * 允许的时钟偏差（用于 producedAt/thisUpdate/nextUpdate 判定）
     */
    private Duration clockSkew = Duration.ofSeconds(30);

    /**
     * 重试策略（最多额外尝试次数）
     */
    private Retry retry = new Retry();

    /**
     * 进入重试所需的最小剩余预算
     */
    private Duration minRetryBudget = Duration.ofMillis(300);

    /**
     * 是否允许 HTTP 重定向（默认关闭；开启时仅 HTTPS 且重新执行完整 TLS/主机名校验）
     */
    private boolean redirectsEnabled = false;

    /**
     * 是否允许非 HTTPS 的 responder/CDP（默认 false，仅开发/测试显式放开；生产必须 HTTPS）
     */
    private boolean allowHttp = false;

    /**
     * 受控 issuer 证书 PEM（可含多张）。叶子证书不带链时用于校验 OCSP/CRL 签名与 issuer 一致性。
     */
    private String issuerCertPem;

    /**
     * OCSP 配置
     */
    private Ocsp ocsp = new Ocsp();

    /**
     * CRL 配置
     */
    private Crl crl = new Crl();

    /**
     * 受控 responder/CDP 鉴权配置
     */
    private Auth auth = new Auth();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public Duration getTotalTimeout() {
        return totalTimeout;
    }

    public void setTotalTimeout(Duration totalTimeout) {
        this.totalTimeout = totalTimeout;
    }

    public Duration getClockSkew() {
        return clockSkew;
    }

    public void setClockSkew(Duration clockSkew) {
        this.clockSkew = clockSkew;
    }

    public Retry getRetry() {
        return retry;
    }

    public void setRetry(Retry retry) {
        this.retry = retry;
    }

    public Duration getMinRetryBudget() {
        return minRetryBudget;
    }

    public void setMinRetryBudget(Duration minRetryBudget) {
        this.minRetryBudget = minRetryBudget;
    }

    public boolean isRedirectsEnabled() {
        return redirectsEnabled;
    }

    public void setRedirectsEnabled(boolean redirectsEnabled) {
        this.redirectsEnabled = redirectsEnabled;
    }

    public boolean isAllowHttp() {
        return allowHttp;
    }

    public void setAllowHttp(boolean allowHttp) {
        this.allowHttp = allowHttp;
    }

    public String getIssuerCertPem() {
        return issuerCertPem;
    }

    public void setIssuerCertPem(String issuerCertPem) {
        this.issuerCertPem = issuerCertPem;
    }

    public Ocsp getOcsp() {
        return ocsp;
    }

    public void setOcsp(Ocsp ocsp) {
        this.ocsp = ocsp;
    }

    public Crl getCrl() {
        return crl;
    }

    public void setCrl(Crl crl) {
        this.crl = crl;
    }

    public Auth getAuth() {
        return auth;
    }

    public void setAuth(Auth auth) {
        this.auth = auth;
    }

    /**
     * 协议规范化：非法模式回退为 {@code ocsp-then-crl} 交由启动校验拒绝（不静默降级）。
     */
    public String normalizedMode() {
        return mode == null ? "ocsp-then-crl" : mode.trim().toLowerCase();
    }

    /**
     * 重试配置
     */
    public static class Retry {
        /**
         * 最多额外尝试次数（默认 1）
         */
        private int maxAttempts = 1;

        /**
         * 基础退避时间
         */
        private Duration baseBackoff = Duration.ofMillis(100);

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }

        public Duration getBaseBackoff() {
            return baseBackoff;
        }

        public void setBaseBackoff(Duration baseBackoff) {
            this.baseBackoff = baseBackoff;
        }
    }

    /**
     * OCSP 配置
     */
    public static class Ocsp {
        /**
         * 显式受控 OCSP responder URL（覆盖证书 AIA）
         */
        private String url;

        /**
         * nonce 策略：required | optional | disabled（平台一致口径，禁止客户端自行猜测降级）
         */
        private String noncePolicy = "required";

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getNoncePolicy() {
            return noncePolicy;
        }

        public void setNoncePolicy(String noncePolicy) {
            this.noncePolicy = noncePolicy;
        }

        public String normalizedNoncePolicy() {
            return noncePolicy == null ? "required" : noncePolicy.trim().toLowerCase();
        }
    }

    /**
     * CRL 配置
     */
    public static class Crl {
        /**
         * 显式受控 CRL 分发点 URL（覆盖证书 CDP）
         */
        private String url;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }

    /**
     * 受控 responder/CDP 鉴权配置
     */
    public static class Auth {
        /**
         * 鉴权模式：none | bearer | mtls
         */
        private String mode = "none";

        /**
         * Bearer token（引用安全配置，不打印）
         */
        private String bearerToken;

        /**
         * mTLS 客户端证书 PEM（独立于设备证书私钥）
         */
        private String clientCertPem;

        /**
         * mTLS 客户端私钥 PEM（独立于设备证书私钥）
         */
        private String clientKeyPem;

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }

        public String getBearerToken() {
            return bearerToken;
        }

        public void setBearerToken(String bearerToken) {
            this.bearerToken = bearerToken;
        }

        public String getClientCertPem() {
            return clientCertPem;
        }

        public void setClientCertPem(String clientCertPem) {
            this.clientCertPem = clientCertPem;
        }

        public String getClientKeyPem() {
            return clientKeyPem;
        }

        public void setClientKeyPem(String clientKeyPem) {
            this.clientKeyPem = clientKeyPem;
        }

        public String normalizedMode() {
            return mode == null ? "none" : mode.trim().toLowerCase();
        }
    }
}
