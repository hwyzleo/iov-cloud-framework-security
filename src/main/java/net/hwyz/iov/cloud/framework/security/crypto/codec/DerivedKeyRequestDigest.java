package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;

/**
 * 派生封装 Provider 幂等请求摘要（FW-SEC-DSN-CR-014 §5.2）。
 * <p>
 * 摘要 SHALL 覆盖（长度前缀、固定字段顺序、UTF-8）：
 * <pre>
 * caller + bizType + rootRef + requestedRootVersionPolicy
 *   + derivationVersion + normalizedAnchorDigest + purpose
 *   + requestId + businessKeyVersion
 *   + recipientCertificateFingerprint + wrappingSuite
 * </pre>
 * 相同 {@code operationId} + 相同摘要返回原信封；不同摘要返回 {@code IDEMPOTENCY_CONFLICT}。
 * framework 侧负责组装受治理输入并计算摘要，Provider 侧重算比对。
 */
public final class DerivedKeyRequestDigest {

    /** 幂等摘要协议标签（首期） */
    public static final String REQUEST_DIGEST_LABEL = "openiov|keyprov-req|v1";

    private DerivedKeyRequestDigest() {
    }

    /**
     * 计算幂等请求摘要（{@code SHA-256(canonicalRequestBytes)}）。
     *
     * @param caller                  调用方标识
     * @param bizType                 业务类型
     * @param rootRef                 受治理根引用
     * @param requestedRootVersionPolicy 请求的根版本策略
     * @param derivationVersion       派生版本
     * @param normalizedAnchorDigest  规范化锚摘要
     * @param purpose                 派生用途
     * @param requestId               请求标识
     * @param businessKeyVersion      VMD 业务版本
     * @param recipientFingerprint    收方证书指纹
     * @param wrappingSuite           封装套件
     * @return 32 字节摘要
     */
    public static byte[] requestDigest(String caller, String bizType, String rootRef,
                                       String requestedRootVersionPolicy, String derivationVersion,
                                       String normalizedAnchorDigest, KeyPurpose purpose,
                                       String requestId, long businessKeyVersion,
                                       String recipientFingerprint, WrappingSuite wrappingSuite) {
        byte[] canonical = CanonicalEncoding.lengthPrefixedUtf8(
                REQUEST_DIGEST_LABEL,
                caller,
                bizType,
                rootRef,
                requestedRootVersionPolicy,
                derivationVersion,
                normalizedAnchorDigest,
                purpose == null ? null : purpose.name(),
                requestId,
                Long.toString(businessKeyVersion),
                recipientFingerprint == null ? null
                        : recipientFingerprint.trim().toLowerCase(java.util.Locale.ROOT),
                wrappingSuite == null ? null : wrappingSuite.name());
        return CanonicalEncoding.sha256(canonical);
    }

    /**
     * 计算幂等请求摘要并返回十六进制（小写）。
     *
     * @return 十六进制摘要
     */
    public static String requestDigestHex(String caller, String bizType, String rootRef,
                                          String requestedRootVersionPolicy, String derivationVersion,
                                          String normalizedAnchorDigest, KeyPurpose purpose,
                                          String requestId, long businessKeyVersion,
                                          String recipientFingerprint, WrappingSuite wrappingSuite) {
        return CanonicalEncoding.hexLower(requestDigest(caller, bizType, rootRef,
                requestedRootVersionPolicy, derivationVersion, normalizedAnchorDigest, purpose,
                requestId, businessKeyVersion, recipientFingerprint, wrappingSuite));
    }
}
