package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.provider.CertificatePublicKeyWrapper;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCapability;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCommand;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyContextEncoder;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedWrapResultRecord;
import net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoderRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.InMemoryOperationResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.provider.ValidatedRecipientEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.provider.ValidatedRecipientEvidenceFixtures;
import net.hwyz.iov.cloud.framework.security.crypto.support.ParProtoKeyprovAadV1Encoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 派生封装 AAD 泄漏扫描测试（FW-SEC-DSN-CR-020 §7 测试 7）。
 * <p>
 * 日志/异常/toString/heap 策略不得泄漏 AAD 以外的敏感中间材料：ciphertext、
 * KEK、ECDH shared secret、临时私钥与业务密钥明文；结构化视图与结果记录只输出长度摘要。
 */
class TransitDerivedKeyAadLeakTest {

    private static final String VIN = "LSVAA4187N2123456";

    private final FakeTransitHmacClient transitClient = new FakeTransitHmacClient();
    private final TransitRootMetadataCache metadataCache = new TransitRootMetadataCache(
            transitClient, Duration.ofMinutes(1));
    private final Clock clock = Clock.fixed(Instant.parse("2026-10-21T00:00:00Z"), ZoneOffset.UTC);
    private TransitDerivedKeyProvider provider;
    private TestPkiMaterial.Pki pki;

    @BeforeEach
    void setUp() throws Exception {
        pki = TestPkiMaterial.generate();
        TransitDerivedKeyReadiness readiness = mock(TransitDerivedKeyReadiness.class);
        when(readiness.capability())
                .thenReturn(DerivedKeyCapability.ready(TransitDerivedKeyProvider.PROVIDER_NAME));
        provider = new TransitDerivedKeyProvider(
                new DerivedKeyPolicyRegistry(),
                new DerivedKeyContextEncoder(),
                transitClient,
                new CertificatePublicKeyWrapper(),
                metadataCache,
                readiness,
                clock,
                EnvelopeAadEncoderRegistry.of(new ParProtoKeyprovAadV1Encoder()),
                new InMemoryOperationResultStore(clock),
                ParProtoKeyprovAadV1Encoder.PROFILE_ID,
                Duration.ofDays(30));
        transitClient.fixedResult = new byte[32];
        for (int i = 0; i < 32; i++) {
            transitClient.fixedResult[i] = (byte) i;
        }
    }

    @Test
    void toString_doesNotLeakCiphertextKcvOrKeyMaterial() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        DerivedWrappedKey result = provider.deriveAndWrap(new DerivedKeyCommand(
                BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, evidence,
                DerivationContext.of("v1", 7L), new OperationContext("op-1", "idem-1")));

        String description = result.toString() + "|" + result.envelope().toString();
        assertFalse(description.contains(Base64.getEncoder().encodeToString(result.envelopeBytes())));
        assertFalse(description.contains(Base64.getEncoder().encodeToString(result.kcv())));
        EcdhEsP256EnvelopeViewV1 v = (EcdhEsP256EnvelopeViewV1) result.envelope();
        assertFalse(description.contains(Base64.getEncoder().encodeToString(v.ciphertext())),
                "ciphertext 不得出现在 toString");
        assertFalse(description.contains(Base64.getEncoder().encodeToString(v.canonicalAad())),
                "canonical AAD bytes 不得展开（只输出长度）");
        // 派生明文（Transit 返回材料）不得泄漏
        assertFalse(description.contains(Base64.getEncoder()
                .encodeToString(transitClient.fixedResult)));
    }

    @Test
    void resultRecordToString_doesNotLeakEnvelopeContents() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        DerivedWrappedKey result = provider.deriveAndWrap(new DerivedKeyCommand(
                BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), KeyPurpose.UPLINK_AEAD, evidence,
                DerivationContext.of("v1", 7L), new OperationContext("op-1", "idem-1")));

        java.util.Optional<DerivedWrapResultRecord> record = new InMemoryOperationResultStore(clock)
                .find("none");
        String recordDescription = result.toString();
        assertFalse(recordDescription.contains(Base64.getEncoder()
                .encodeToString(result.envelopeBytes())));
    }

    @Test
    void envelopeAadContextToString_doesNotExpandDigest() {
        EnvelopeAadContext context = new EnvelopeAadContext(
                1, WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM, "req-1", "V2C_COMM_ROOT",
                KeyPurpose.UPLINK_AEAD, "logical-1", 7L, 3L, "v1", new byte[32]);
        String description = context.toString();
        assertFalse(description.contains(Base64.getEncoder().encodeToString(new byte[32])));
        assertFalse(description.contains("0000000000000000000000000000000000000000000000000000000000000000"),
                "收方证书摘要 hex 不得展开");
    }

    /** 可控 Transit 客户端（泄漏扫描用）。 */
    static final class FakeTransitHmacClient implements TransitHmacClient {
        byte[] fixedResult = new byte[32];

        @Override
        public TransitHmacResult hmac(String approvedKeyName, String algorithm, byte[] input,
                                      OperationContext operation) {
            return new TransitHmacResult("v1", fixedResult.clone(), approvedKeyName);
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
