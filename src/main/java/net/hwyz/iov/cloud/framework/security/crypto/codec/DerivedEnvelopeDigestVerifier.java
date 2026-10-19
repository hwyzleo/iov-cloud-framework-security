package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeView;

/**
 * 公开 canonical 信封摘要校验 API（FW-SEC-DSN-CR-015 §4.3；REQ-015-3/REQ-015-4）。
 * <p>
 * 下游（VMD 协议 Adapter）在把 FW 结果映射为 wire 之前 SHALL 调用本 API 复核唯一
 * {@code envelopeDigest}。入参<strong>只能</strong>是 framework 公开的
 * {@link DerivedWrappedKeyEnvelopeView}；实现<strong>不得</strong>要求或暴露私有
 * {@code DerivedWrappedKeyEnvelopeV1}，调用方也不得构造私有 envelope 类型。
 * <p>
 * 契约：
 * <ul>
 *   <li>按 {@code envelopeFormat + formatVersion} 分派到内部 canonical codec；</li>
 *   <li>从 view 的全部 digest-bound 字段重建 {@code canonicalEnvelopeBytesWithoutDigest}，
 *       复算 SHA-256 并与 {@code view.envelopeDigest()} <strong>恒定时间</strong>比较；</li>
 *   <li>未知 format/version、必填字段缺失、长度非法或摘要不匹配时抛出
 *       {@link net.hwyz.iov.cloud.framework.security.crypto.exception.DerivedEnvelopeIntegrityException}，
 *       <strong>不</strong>返回布尔值由调用方忽略；</li>
 *   <li>不负责 PAR-PROTO deterministic serialization，也不计算第二套 wire digest
 *       （canonical envelope/AAD/digest 的唯一权威在 framework core）。</li>
 * </ul>
 */
public interface DerivedEnvelopeDigestVerifier {

    /**
     * 复核公开信封视图携带的 {@code envelopeDigest} 与其 canonical 内容一致。
     *
     * @param view 公开、只读、版本化的信封视图
     * @throws NullPointerException              视图为 null
     * @throws net.hwyz.iov.cloud.framework.security.crypto.exception.DerivedEnvelopeIntegrityException
     *         格式/版本不受支持、字段非法或摘要不匹配（确定性失败，不可重试）
     */
    void verify(DerivedWrappedKeyEnvelopeView view);
}
