package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import java.util.Optional;

/**
 * 领域证书目录薄索引 SPI（FW-SEC-DSN-CR-012 §5）。
 * <p>
 * 由 VMD/TSP/KTS 等消费方实现，仅暴露自身权威的领域索引，例如
 * {@code certSerial → pkiRequestId}、{@code deviceSn → active certSerial}。
 * <p>
 * 安全边界：
 * <ul>
 *   <li>只表达「去哪里找」，不返回未经 framework 校验即可使用的信任结论；</li>
 *   <li>framework 不拥有主体/serial 目录权威，无来源时不得自行构造映射；</li>
 *   <li>多个 Adapter 同时命中且结果不一致时由 framework 拒绝（不按 Bean 顺序取首个）。</li>
 * </ul>
 */
@FunctionalInterface
public interface CertificateReferenceDirectory {

    /**
     * 把显式引用（可能仅含 serial/主体，也可能已带证据字段）解析为受控 locator。
     *
     * @param ref 证书引用
     * @return 受控 locator；无权威映射时返回 {@link Optional#empty()}
     */
    Optional<CertificateLocator> locate(DeviceCertificateRef ref);
}
