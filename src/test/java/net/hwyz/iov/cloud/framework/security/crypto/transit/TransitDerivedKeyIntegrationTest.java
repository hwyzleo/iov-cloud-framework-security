package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.DefaultKeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.KeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.model.businesskey.RecipientRef;
import net.hwyz.iov.cloud.framework.security.crypto.provider.CertificatePublicKeyWrapper;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCapability;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyContextEncoder;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyProviderRouter;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateEvidenceValidator;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.CertificateResolvePolicy;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceCertificateRef;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.EvidenceSource;
import net.hwyz.iov.cloud.framework.security.crypto.support.ReferenceDerivedKeyUnwrapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * DERIVED_ROOT 本地 Transit 派生全链路集成测试（FW-SEC-DSN-CR-019 §4/§5.3）。
 * <p>
 * 门面（完整证书校验）→ Router(local-wrap) → TransitDerivedKeyProvider → Transit HMAC(fake)
 * → 本地证书公钥封装 → canonical 信封 → 模拟 TBOX 解封闭环；验证：
 * <ul>
 *   <li>VMD 公共门面/DTO 不变，无代码修改即走本地 Provider；</li>
 *   <li>local-wrap 失败<strong>不</strong>自动改走 legacy Feign（kmsClient.deriveAndWrap 恒为 0）；</li>
 *   <li>非 V2C DERIVED_ROOT 在 local-wrap 下 fail-closed（不自动套用 V2C 标签）。</li>
 * </ul>
 */
class TransitDerivedKeyIntegrationTest {

    private static final String VIN = "LSVAA4187N2123456";

    private KmsClient kmsClient;
    private KeyProvisioningTemplate template;
    private TestPkiMaterial.Pki pki;
    private FakeTransitClient transitClient;

    @BeforeEach
    void setUp() throws Exception {
        CryptoProperties properties = new CryptoProperties();
        properties.getProvisioning().setEnabled(true);
        properties.getProvisioning().getDerivedKey().setProvider("openbao-transit-local-wrap");
        CryptoProperties.Provisioning.DerivedKey.RootPolicy root =
                new CryptoProperties.Provisioning.DerivedKey.RootPolicy();
        root.setTransitKey("v2c-comm-root");
        root.setHmacAlgorithm("sha2-256");
        root.setPurposes(java.util.List.of("UPLINK_AEAD", "DOWNLINK_AEAD"));
        root.setWrapModes(java.util.List.of("DEVICE_CERT_PUBLIC_KEY"));
        properties.getProvisioning().getDerivedKey().getRoots().put("V2C_COMM_ROOT", root);

        pki = TestPkiMaterial.generate();
        CertResolver certResolver = mock(CertResolver.class);
        when(certResolver.resolve(any(DeviceCertificateRef.class), any(CertificateResolvePolicy.class)))
                .thenReturn(CertificateEvidenceValidator.fromCertificateDer(
                        pki.leafCert().getEncoded(), EvidenceSource.PROVIDER_QUERY));

        kmsClient = mock(KmsClient.class);
        transitClient = new FakeTransitClient();
        TransitRootMetadataCache metadataCache = new TransitRootMetadataCache(
                transitClient, Duration.ofMinutes(1));
        TransitDerivedKeyReadiness readiness = mock(TransitDerivedKeyReadiness.class);
        when(readiness.capability())
                .thenReturn(DerivedKeyCapability.ready(TransitDerivedKeyProvider.PROVIDER_NAME));
        TransitDerivedKeyProvider provider = new TransitDerivedKeyProvider(
                new DerivedKeyPolicyRegistry(), new DerivedKeyContextEncoder(), transitClient,
                new CertificatePublicKeyWrapper(), metadataCache, readiness,
                Clock.fixed(Instant.parse("2026-10-21T00:00:00Z"), ZoneOffset.UTC));
        DerivedKeyProviderRouter router = new DerivedKeyProviderRouter(
                DerivedKeyProviderRouter.LOCAL_WRAP_PROVIDER, provider, null);

        template = new DefaultKeyProvisioningTemplate(kmsClient, mock(CryptoMetrics.class), properties,
                null, certResolver, null, null, router);
    }

    @Test
    void endToEnd_localWrap_unwrapsToSameMaterialAndKcv() throws Exception {
        transitClient.deterministic = true;
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        DerivedWrappedKey result = template.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor,
                KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate("cert-001"),
                DerivationContext.of("v1", 7L), "op-1", "idem-1");

        // 固定向量：Transit 收到 openiov|v2c|v1|VIN|UPLINK_AEAD
        assertArrayEquals(("openiov|v2c|v1|" + VIN + "|UPLINK_AEAD")
                .getBytes(StandardCharsets.UTF_8), transitClient.lastInput);
        // KCV = first_3(SHA-256(HMAC))；信封可解封出同一材料
        EcdhEsP256EnvelopeViewV1 view = (EcdhEsP256EnvelopeViewV1) result.envelope();
        assertNotNull(view, "ECDH-ES v1 结果必须携带结构化视图");
        assertEquals(WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, result.wrappingSuite());
        byte[] expected = CanonicalEncoding.sha256(
                ("openiov|v2c|v1|" + VIN + "|UPLINK_AEAD").getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyKcv
                .first3Sha256(expected), result.kcv());

        // 公共门面/DTO 不变：返回 DerivedWrappedKey，无代码修改即走本地 Provider
        verify(kmsClient, never()).deriveAndWrap(any(), any(), any(), any());
    }

    @Test
    void localWrap_transitFailure_doesNotFallbackToLegacy() {
        transitClient.failure = TransitException.sealed("hmac:v2c-comm-root");
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        assertThrows(TransitException.class, () -> template.deriveAndWrap(BizType.V2C_COMM_ROOT,
                anchor, KeyPurpose.UPLINK_AEAD, new RecipientRef.DeviceCertificate("cert-001"),
                DerivationContext.of("v1", 7L), "op-1", "idem-1"));
        // 新 Provider 失败不自动改走 Feign（禁止运行时动态回退，FW-SEC-DSN-CR-019 §12）
        verify(kmsClient, never()).deriveAndWrap(any(), any(), any(), any());
    }

    @Test
    void localWrap_nonV2cDerivedRoot_failClosed() {
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        TransitException ex = assertThrows(TransitException.class, () -> template.deriveAndWrap(
                BizType.IMMO_GROUP_KEY, anchor, KeyPurpose.UPLINK_AEAD,
                new RecipientRef.DeviceCertificate("cert-001"), DerivationContext.of("v1", 7L),
                "op-1", "idem-1"));
        assertEquals(net.hwyz.iov.cloud.framework.security.crypto.exception.TransitReason.DERIVATION_POLICY_INVALID,
                ex.transitReason());
        verify(kmsClient, never()).deriveAndWrap(any(), any(), any(), any());
    }

    @Test
    void endToEnd_roundTrip_unwrapWithReference() throws Exception {
        // 用模拟 TBOX 私钥解封：验证信封自描述（仅凭信封即可解封，无需外部隐式参数）
        KeyAnchor anchor = KeyAnchor.vin(VIN);
        DerivedWrappedKey result = template.deriveAndWrap(BizType.V2C_COMM_ROOT, anchor,
                KeyPurpose.DOWNLINK_AEAD, new RecipientRef.DeviceCertificate("cert-001"),
                DerivationContext.of("v1", 7L), "op-2", "idem-2");
        byte[] keyMaterial = CanonicalEncoding.sha256(transitClient.lastInput);
        byte[] unwrapped = ReferenceDerivedKeyUnwrapper.unwrap(pki.leafKeyPair().getPrivate(),
                toEnvelope(result));
        assertArrayEquals(keyMaterial, unwrapped);
    }

    private static net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1 toEnvelope(
            DerivedWrappedKey result) {
        EcdhEsP256EnvelopeViewV1 v = (EcdhEsP256EnvelopeViewV1) result.envelope();
        return new net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1(
                net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1.V1,
                v.wrappingSuite(),
                v.serverEphemeralPublicKey(), v.hkdfSalt(), v.hkdfContextVersion(),
                v.nonce(), v.ciphertext(), v.authenticationTag(),
                v.canonicalAad(), v.aadDigest(),
                CanonicalEncoding.hexLower(v.recipientCertificateDigest()),
                v.logicalKeyId(), v.purpose(), v.businessKeyVersion(), v.rootKeyVersion(),
                v.derivationVersion(), v.keyCheckValue(), v.operationId(), v.envelopeDigest());
    }

    /** 确定性 Transit 客户端：HMAC = SHA-256(input)。 */
    static final class FakeTransitClient implements TransitHmacClient {
        boolean deterministic;
        TransitException failure;
        byte[] lastInput;

        @Override
        public TransitHmacResult hmac(String approvedKeyName, String algorithm, byte[] input,
                                      OperationContext operation) {
            lastInput = input == null ? null : input.clone();
            if (failure != null) {
                throw failure;
            }
            return new TransitHmacResult("v1", CanonicalEncoding.sha256(input), approvedKeyName);
        }

        @Override
        public TransitKeyMetadata readMetadata(String approvedKeyName) {
            return new TransitKeyMetadata("v2c-comm-root", "aes256-gcm96", false, true, 3, 3, 1);
        }

        @Override
        public TransitSystemHealth probeHealth() {
            return new TransitSystemHealth(true, false, false);
        }
    }
}
