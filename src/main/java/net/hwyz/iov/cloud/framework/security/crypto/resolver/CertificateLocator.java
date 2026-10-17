package net.hwyz.iov.cloud.framework.security.crypto.resolver;

/**
 * 领域目录 locator（FW-SEC-DSN-CR-012 §5）。
 * <p>
 * 领域目录只表达「去哪里找证书」，返回受控 locator；framework 据此回到
 * requestId/result store 或 Provider serial query 取材料，<b>不</b>接受目录直接返回的信任结论。
 */
public sealed interface CertificateLocator {

    /**
     * 映射到证书注册 requestId。
     */
    record EnrollmentRequest(String requestId) implements CertificateLocator {
        public EnrollmentRequest {
            if (requestId == null || requestId.isBlank()) {
                throw new IllegalArgumentException("requestId must not be blank");
            }
        }
    }

    /**
     * 映射到 Provider 的 serial 查询键。
     */
    record ProviderSerial(String serial) implements CertificateLocator {
        public ProviderSerial {
            if (serial == null || serial.isBlank()) {
                throw new IllegalArgumentException("serial must not be blank");
            }
        }
    }
}
