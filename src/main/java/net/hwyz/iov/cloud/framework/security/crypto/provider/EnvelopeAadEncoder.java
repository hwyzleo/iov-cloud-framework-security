package net.hwyz.iov.cloud.framework.security.crypto.provider;

import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadContext;

/**
 * 协议无关信封 AAD 编码 SPI（FW-SEC-DSN-CR-020 §2）。
 * <p>
 * 由 VMD 等消费方注册特定协议（如 PAR-PROTO）的 canonical AAD profile；framework 在
 * AES-256-GCM 加密<strong>之前</strong>经受控 {@link EnvelopeAadEncoderRegistry} 解析
 * 当前 profile 并取得 AAD 字节，绝不在加密后替换 AAD 或重算 tag。
 * <p>
 * <strong>实现契约</strong>：
 * <ul>
 *   <li>{@code profileId()} 必须稳定、非空、唯一（registry 拒绝重复/空值）；</li>
 *   <li>{@code encode(context)} 必须<strong>确定性</strong>：相同上下文必须返回字节级相同输出
 *       （同 operation 重放依赖；registry 注册时用固定向量自检，非确定输出 fail-closed）；</li>
 *   <li>输出必须是有界 canonical 字节（默认 ≤ 1 KiB），不得包含敏感材料或依赖隐式上下文；</li>
 *   <li>encode 不得有副作用，不得抛出并吞掉可恢复状态；异常由 framework fail-closed 分类。</li>
 * </ul>
 * framework 不依赖任何协议 classpath；本 SPI 是 FW 与 VMD 协议边界（CR-015 RD-015-2/RD-015-3）。
 */
public interface EnvelopeAadEncoder {

    /**
     * 协议 profile 标识（如 {@code PAR_PROTO_KEYPROV_AAD_V1}）。
     *
     * @return 稳定、非空、唯一标识
     */
    String profileId();

    /**
     * 将非敏感 AAD 上下文编码为 canonical AAD 字节（加密前使用）。
     *
     * @param context 非敏感 AAD 上下文（含收方证书摘要）
     * @return canonical AAD 字节（调用方防御性复制）
     */
    byte[] encode(EnvelopeAadContext context);
}
