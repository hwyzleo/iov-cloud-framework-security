package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

/**
 * step-ca 一次性令牌（OTT）提供者 SPI（FW-SEC-DSN-CR-008 §4）
 * <p>
 * 默认实现 {@link JwkStepCaTokenProvider} 在进程内完成 JOSE 签名；
 * 扩展点：KMS/HSM/远程 OTT 服务实现（如后续需要集中隔离，新增远程实现即可）。
 * <p>
 * 令牌必须短生命周期（默认 5 分钟且可缩短）、包含唯一 jti=requestId+nonce、
 * 严禁缓存复用 OTT。
 */
public interface StepCaTokenProvider {

    /**
     * 生成一次性令牌。
     *
     * @param request 令牌请求
     * @return 序列化令牌（JWT）
     */
    String createToken(StepCaTokenRequest request);
}
