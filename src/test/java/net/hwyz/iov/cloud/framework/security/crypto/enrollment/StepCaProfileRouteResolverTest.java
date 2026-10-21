package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Profile → signer 路由解析单元测试（FW-SEC-DSN-CR-018 §7，RD-018-4/5）。
 */
class StepCaProfileRouteResolverTest {

    private JwkSignerDescriptor signer(String ref, String provisioner, String kid) throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID(kid).algorithm(JWSAlgorithm.ES256).generate();
        return new JwkSignerDescriptor(ref, provisioner, kid,
                JwkPrivateKeyHandle.fromContent(key.toJSONString(), null));
    }

    private StepCaProfilePolicy policy(String profileName, String provisioner, String kid, String signerRef) {
        return new StepCaProfilePolicy(profileName, provisioner, kid, signerRef,
                Duration.ofDays(365), List.of("EC_P256"), List.of("CLIENT_AUTH"), "TBOX");
    }

    @Test
    void resolve_shouldUseExplicitSignerRefRoute() throws Exception {
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(Map.of(
                "tsp-client", signer("tsp-client", "openiov", "kid-1")));

        EffectiveStepCaProfileRoute route = StepCaProfileRouteResolver.resolve(
                policy("TBOX_TSP_CLIENT", "openiov", "kid-1", "tsp-client"), registry);

        assertEquals("tsp-client", route.signerRef());
        assertEquals("openiov", route.provisioner());
        assertEquals("kid-1", route.kid());
    }

    @Test
    void resolve_shouldFallBackToLegacy_whenNoSignerRef() throws Exception {
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(Map.of(
                StepCaProfileRouteResolver.LEGACY_SIGNER_REF,
                signer(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, null, null)));

        EffectiveStepCaProfileRoute route = StepCaProfileRouteResolver.resolve(
                policy("TBOX_TSP_CLIENT", "openiov", "kid-1", null), registry);

        assertEquals(StepCaProfileRouteResolver.LEGACY_SIGNER_REF, route.signerRef());
        assertEquals("openiov", route.provisioner(), "legacy route 使用 Profile 的 provisioner（RD-018-4）");
        assertEquals("kid-1", route.kid(), "legacy route 使用 Profile 的 kid（RD-018-4）");
    }

    @Test
    void resolve_shouldReject_whenExplicitSignerMissing() {
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(Map.of());
        assertThrows(IllegalStateException.class,
                () -> StepCaProfileRouteResolver.resolve(
                        policy("TBOX_TSP_CLIENT", "openiov", "kid-1", "missing-signer"), registry));
    }

    @Test
    void resolve_shouldReject_whenLegacyMissing() {
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(Map.of());
        assertThrows(IllegalStateException.class,
                () -> StepCaProfileRouteResolver.resolve(
                        policy("TBOX_TSP_CLIENT", "openiov", "kid-1", null), registry),
                "legacy 单 JWK 不存在且 Profile 未声明 signerRef 时启动失败（RD-018-4）");
    }

    @Test
    void resolve_shouldReject_onProvisionerMismatch() throws Exception {
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(Map.of(
                "tsp-client", signer("tsp-client", "other-provisioner", "kid-1")));

        assertThrows(IllegalStateException.class,
                () -> StepCaProfileRouteResolver.resolve(
                        policy("TBOX_TSP_CLIENT", "openiov", "kid-1", "tsp-client"), registry),
                "signer 的 provisioner 与 Profile route 冲突，不得覆盖（RD-018-5）");
    }

    @Test
    void resolve_shouldReject_onKidMismatch() throws Exception {
        JwkSignerRegistry registry = new DefaultJwkSignerRegistry(Map.of(
                "tsp-client", signer("tsp-client", "openiov", "other-kid")));

        assertThrows(IllegalStateException.class,
                () -> StepCaProfileRouteResolver.resolve(
                        policy("TBOX_TSP_CLIENT", "openiov", "kid-1", "tsp-client"), registry),
                "signer 的 kid 与 Profile route 冲突，不得覆盖（RD-018-5）");
    }
}
