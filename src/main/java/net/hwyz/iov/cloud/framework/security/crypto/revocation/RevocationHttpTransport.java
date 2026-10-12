package net.hwyz.iov.cloud.framework.security.crypto.revocation;

import java.net.URI;
import java.time.Duration;

/**
 * 吊销查询 HTTP 传输抽象（FW-SEC-DSN-CR-010 §6）
 * <p>
 * 由 {@link HttpRevocationTransport} 使用 framework 管理的有界 HTTP client 实现；
 * 单元测试可注入桩实现，无需真实网络。
 */
public interface RevocationHttpTransport {

    /**
     * HTTP GET（CRL 拉取）。
     *
     * @param uri        目标 URI（HTTPS）
     * @param readTimeout 本次读超时（受总预算约束）
     * @param accept     Accept 头（可为空）
     */
    Response get(URI uri, Duration readTimeout, String accept);

    /**
     * HTTP POST（OCSP 查询）。
     *
     * @param uri        目标 URI（HTTPS）
     * @param body       请求体（DER）
     * @param contentType Content-Type
     * @param accept     Accept 头
     * @param readTimeout 本次读超时（受总预算约束）
     */
    Response post(URI uri, byte[] body, String contentType, String accept, Duration readTimeout);

    /**
     * 传输响应
     *
     * @param statusCode HTTP 状态码
     * @param body       响应体
     * @param finalUri   最终 URI（重定向后可不同；默认关闭重定向）
     */
    record Response(int statusCode, byte[] body, URI finalUri) {
    }
}
