package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import java.util.Set;

/**
 * 命名 JWK signer 注册表（FW-SEC-DSN-CR-018 §6）。
 * <p>
 * 启动阶段构建为<strong>不可变</strong> registry（解析配置、加载/解密 JWK、验证算法、
 * 提取 public JWK、检查 kid 与 Provisioner route）。运行时按 {@code signerRef} 查找唯一 signer；
 * 查找失败必须在 HTTP 调用前拒绝（FW-SEC-DSN-CR-018 §8）。
 */
public interface JwkSignerRegistry {

    /**
     * 按 signerRef 查找 signer；不存在则抛异常拒绝（fail-closed，HTTP 调用数为 0）。
     */
    JwkSignerDescriptor require(String signerRef);

    /**
     * 已登记 signer 引用集合（不含私钥材料）。
     */
    Set<String> signerRefs();
}
