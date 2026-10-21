package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 命名 JWK signer 注册表单元测试（FW-SEC-DSN-CR-018 §6/§8）。
 */
class JwkSignerRegistryTest {

    private JwkSignerDescriptor descriptor(String ref, String provisioner, String kid) throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID(kid).algorithm(JWSAlgorithm.ES256).generate();
        return new JwkSignerDescriptor(ref, provisioner, kid,
                JwkPrivateKeyHandle.fromContent(key.toJSONString(), null));
    }

    @Test
    void require_shouldReturnRegisteredSigner() throws Exception {
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(Map.of(
                "tsp-client", descriptor("tsp-client", "openiov", "kid-1")));

        JwkSignerDescriptor signer = registry.require("tsp-client");

        assertEquals("tsp-client", signer.signerRef());
        assertEquals("openiov", signer.provisioner());
        assertEquals("kid-1", signer.kid());
        assertNotNull(signer.privateKeyHandle());
    }

    @Test
    void require_shouldRejectUnknownSigner() {
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(Map.of());
        assertThrows(IllegalStateException.class, () -> registry.require("missing-signer"),
                "运行时 registry 查找失败必须拒绝（fail-closed）");
    }

    @Test
    void registry_shouldBeImmutable_againstBackingMapMutation() throws Exception {
        Map<String, JwkSignerDescriptor> backing = new LinkedHashMap<>();
        backing.put("a", descriptor("a", "openiov", "kid-a"));
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(backing);

        // 构造后修改入参 map 不得影响 registry
        backing.put("b", descriptor("b", "openiov", "kid-b"));
        assertThrows(IllegalStateException.class, () -> registry.require("b"));
    }

    @Test
    void signerRefs_shouldBeUnmodifiable() throws Exception {
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(Map.of(
                "a", descriptor("a", "openiov", "kid-a")));
        assertThrows(UnsupportedOperationException.class, () -> registry.signerRefs().add("b"));
    }
}
