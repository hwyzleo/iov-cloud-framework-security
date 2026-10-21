package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;

/**
 * Transit 专用客户端 SPI（FW-SEC-DSN-CR-019 §5.2）。
 * <p>
 * 首期只允许：
 * <pre>
 * POST /v1/transit/hmac/{approved-root}/{algorithm}
 * GET  /v1/transit/keys/{approved-root}
 * </pre>
 * 根密钥名由受治理策略传入，客户端不得管理/导出/轮换/删除 Transit Key。
 * 客户端必须关闭 body 日志、自动请求/响应转储和异常 body 回显；
 * Token 经认证组件短期持有并只保存在其内存中。
 */
public interface TransitHmacClient {

    /**
     * 对受治理根执行 HMAC 派生。
     *
     * @param approvedKeyName 批准根密钥名（如 {@code v2c-comm-root}）
     * @param algorithm       HMAC 算法（首期 {@code sha2-256}）
     * @param input           派生输入（有界 byte[]）
     * @param operation       操作上下文（对账/幂等）
     * @return 严格解析的 HMAC 结果
     * @throws TransitException 按稳定 reason 分类失败
     */
    TransitHmacResult hmac(String approvedKeyName, String algorithm, byte[] input,
                           OperationContext operation);

    /**
     * 读取根密钥元数据（readiness/rootKeyVersion）。
     *
     * @param approvedKeyName 批准根密钥名
     * @return 根元数据
     * @throws TransitException 按稳定 reason 分类失败
     */
    TransitKeyMetadata readMetadata(String approvedKeyName);

    /**
     * OpenBao 系统健康探测（仅 readiness 使用；GET /v1/sys/health）。
     *
     * @return 健康快照
     * @throws TransitException 探测失败
     */
    TransitSystemHealth probeHealth();
}
