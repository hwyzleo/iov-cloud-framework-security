package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 密钥材料模型路由不匹配（FW-SEC-DSN-CR-013 §7.3）。
 * <p>
 * 当业务类型声明的 {@code materialModel} 与所调用门面不一致时 fail-closed 抛出，禁止隐式回退：
 * <ul>
 *   <li>{@code DERIVED_ROOT} 误入 {@code BusinessKeyMaterialTemplate}（随机材料门面）；</li>
 *   <li>非 {@code DERIVED_ROOT} 误入 {@code KeyProvisioningTemplate.deriveAndWrap}（根派生门面）。</li>
 * </ul>
 */
public class KeyMaterialModelMismatchException extends CryptoException {

    public KeyMaterialModelMismatchException(String message) {
        super(Reason.MATERIAL_MODEL_MISMATCH, message);
    }

    public KeyMaterialModelMismatchException(String message, Throwable cause) {
        super(Reason.MATERIAL_MODEL_MISMATCH, message, cause);
    }
}
