package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 默认不可变 JWK signer 注册表实现（FW-SEC-DSN-CR-018 §6）。
 * <p>
 * 构造时对入参做防御性拷贝并不可变化；运行时 {@link #require} 查找失败即拒绝。
 */
public final class DefaultJwkSignerRegistry implements JwkSignerRegistry {

    private final Map<String, JwkSignerDescriptor> signers;

    public DefaultJwkSignerRegistry(Map<String, JwkSignerDescriptor> signers) {
        Map<String, JwkSignerDescriptor> copy = new LinkedHashMap<>();
        if (signers != null) {
            copy.putAll(signers);
        }
        this.signers = Collections.unmodifiableMap(copy);
    }

    @Override
    public JwkSignerDescriptor require(String signerRef) {
        Objects.requireNonNull(signerRef, "signerRef must not be null");
        JwkSignerDescriptor descriptor = signers.get(signerRef);
        if (descriptor == null) {
            throw new IllegalStateException(
                    "No JWK signer registered for signerRef='" + signerRef + "'; configured signers="
                            + signers.keySet() + " (FW-SEC-DSN-CR-018 §8, fail-closed before HTTP)");
        }
        return descriptor;
    }

    @Override
    public Set<String> signerRefs() {
        return signers.keySet();
    }
}
