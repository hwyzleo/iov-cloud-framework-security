package net.hwyz.iov.cloud.framework.security.crypto.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.JwkSignerRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.StepCaProfileRouteResolver;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * step-ca 多 JWK signer registry 工厂单元测试（FW-SEC-DSN-CR-018 §5/§8/§10）。
 * <p>
 * 覆盖：legacy 兼容（RD-018-4）、多 signer 构建、signerRef 保留名/格式校验（§8.1）、
 * 私钥来源冲突（§8.4）、配置 kid 与 JWK kid 一致性（§8.5）等 fail-closed 场景。
 * Profile→signer 路由解析负向用例见 {@code StepCaProfileRouteResolverTest}。
 */
class StepCaJwkSignerRegistryFactoryTest {

    private ECKey generateKey(String kid) throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(kid).algorithm(JWSAlgorithm.ES256).generate();
    }

    private CryptoProperties.Pki.StepCa stepCa() {
        CryptoProperties properties = new CryptoProperties();
        properties.getPki().getStepCa().setTokenProvider("jwk");
        return properties.getPki().getStepCa();
    }

    private CryptoProperties.Pki.JwkSignerProperties signerConfig(String provisioner, String kid,
                                                                  String jwkJson) {
        CryptoProperties.Pki.JwkSignerProperties signer = new CryptoProperties.Pki.JwkSignerProperties();
        signer.setProvisioner(provisioner);
        signer.setKid(kid);
        signer.setPrivateKeyContent(jwkJson);
        return signer;
    }

    @Test
    void create_legacyOnly_registersLegacySigner() throws Exception {
        // 阶段 A：仅 legacy 单 JWK → 映射为保留 __legacy__（RD-018-4）
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().setPrivateKeyContent(generateKey("kid-1").toJSONString());

        JwkSignerRegistry registry = StepCaJwkSignerRegistryFactory.create(stepCa);

        assertTrue(registry.signerRefs().contains(StepCaProfileRouteResolver.LEGACY_SIGNER_REF));
        assertEquals(null, registry.require(StepCaProfileRouteResolver.LEGACY_SIGNER_REF).provisioner(),
                "legacy signer 不绑定 provisioner/kid（route 取自 Profile）");
    }

    @Test
    void create_multiSigner_registersAllSigners() throws Exception {
        // 阶段 B/C：两个命名 signer 各自持钥
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().getSigners().put("tsp-client",
                signerConfig("openiov", "tsp-kid", generateKey("tsp-kid").toJSONString()));
        stepCa.getJwk().getSigners().put("tbox-device-ecdh-v1",
                signerConfig("tbox-device-ecdh-v1", "ecdh-kid", generateKey("ecdh-kid").toJSONString()));

        JwkSignerRegistry registry = StepCaJwkSignerRegistryFactory.create(stepCa);

        assertEquals(Set.of("tsp-client", "tbox-device-ecdh-v1"), registry.signerRefs());
        assertEquals("openiov", registry.require("tsp-client").provisioner());
        assertEquals("ecdh-kid", registry.require("tbox-device-ecdh-v1").kid());
    }

    @Test
    void create_shouldReject_reservedSignerRef() throws Exception {
        // §8.1：__legacy__ 为内部保留引用
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().getSigners().put("__legacy__",
                signerConfig("openiov", "kid-1", generateKey("kid-1").toJSONString()));

        assertThrows(IllegalStateException.class, () -> StepCaJwkSignerRegistryFactory.create(stepCa));
    }

    @Test
    void create_shouldReject_invalidSignerRefFormat() throws Exception {
        // §8.1：含空格 / __ 前缀 的 signerRef 拒绝
        for (String badRef : new String[]{"tsp client", "__reserved"}) {
            CryptoProperties.Pki.StepCa stepCa = stepCa();
            stepCa.getJwk().getSigners().put(badRef,
                    signerConfig("openiov", "kid-1", generateKey("kid-1").toJSONString()));
            assertThrows(IllegalStateException.class,
                    () -> StepCaJwkSignerRegistryFactory.create(stepCa),
                    "signerRef='" + badRef + "' 应被拒绝");
        }
    }

    @Test
    void create_shouldReject_privateKeySourceConflict() throws Exception {
        // §8.4：file 与 content 同时配置 → 私钥来源冲突
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().setPrivateKeyFile("/run/secrets/legacy.jwk");
        stepCa.getJwk().setPrivateKeyContent(generateKey("kid-1").toJSONString());

        assertThrows(IllegalStateException.class, () -> StepCaJwkSignerRegistryFactory.create(stepCa));
    }

    @Test
    void create_shouldReject_signerKidConflictWithJwk() throws Exception {
        // §8.5：signer 配置 kid 与 JWK 自身 kid 不一致
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.getJwk().getSigners().put("tsp-client",
                signerConfig("openiov", "configured-kid", generateKey("jwk-kid").toJSONString()));

        assertThrows(IllegalStateException.class, () -> StepCaJwkSignerRegistryFactory.create(stepCa));
    }

    @Test
    void create_shouldReject_unsupportedTokenProvider() {
        CryptoProperties.Pki.StepCa stepCa = stepCa();
        stepCa.setTokenProvider("nimbus");
        assertThrows(IllegalStateException.class, () -> StepCaJwkSignerRegistryFactory.create(stepCa));
    }
}
