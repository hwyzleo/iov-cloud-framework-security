package net.hwyz.iov.cloud.framework.security.crypto.transit;

import net.hwyz.iov.cloud.framework.security.crypto.client.OperationContext;
import net.hwyz.iov.cloud.framework.security.crypto.codec.CanonicalEncoding;
import net.hwyz.iov.cloud.framework.security.crypto.codec.DerivedKeyEnvelopeCanonical;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import net.hwyz.iov.cloud.framework.security.crypto.exception.DerivedWrapIdempotencyConflictException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.TransitReason;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivationContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKeyEnvelopeV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.EcdhEsP256EnvelopeViewV1;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeAadContext;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyAnchor;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyPurpose;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappingSuite;
import net.hwyz.iov.cloud.framework.security.crypto.provider.CertificatePublicKeyWrapper;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCapability;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyCommand;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyContextEncoder;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyKcv;
import net.hwyz.iov.cloud.framework.security.crypto.provider.DerivedKeyPolicyRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoder;
import net.hwyz.iov.cloud.framework.security.crypto.provider.EnvelopeAadEncoderRegistry;
import net.hwyz.iov.cloud.framework.security.crypto.provider.InMemoryOperationResultStore;
import net.hwyz.iov.cloud.framework.security.crypto.provider.ValidatedRecipientEvidence;
import net.hwyz.iov.cloud.framework.security.crypto.provider.ValidatedRecipientEvidenceFixtures;
import net.hwyz.iov.cloud.framework.security.crypto.support.ParProtoKeyprovAadV1Encoder;
import net.hwyz.iov.cloud.framework.security.crypto.support.ReferenceDerivedKeyUnwrapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * TransitDerivedKeyProvider 主流程测试（FW-SEC-DSN-CR-019 §5.3）。
 * <p>
 * 覆盖：策略校验→最终门禁→context 编码→Transit HMAC→长度校验→本地 Wrap→KCV→逻辑引用→
 * finally 清零；失败路径（Transit 失败/长度非法/证据过期/套件不匹配）fail-closed。
 */
class TransitDerivedKeyProviderTest {

    private static final String VIN = "LSVAA4187N2123456";

    private final FakeTransitHmacClient transitClient = new FakeTransitHmacClient();
    private final TransitRootMetadataCache metadataCache = new TransitRootMetadataCache(
            transitClient, Duration.ofMinutes(1));
    private final Clock clock = Clock.fixed(Instant.parse("2026-10-21T00:00:00Z"), ZoneOffset.UTC);
    private TransitDerivedKeyProvider provider;
    private InMemoryOperationResultStore resultStore;
    private CountingEncoder countingEncoder;
    private TestPkiMaterial.Pki pki;

    @BeforeEach
    void setUp() throws Exception {
        pki = TestPkiMaterial.generate();
        TransitDerivedKeyReadiness readiness = mock(TransitDerivedKeyReadiness.class);
        when(readiness.capability())
                .thenReturn(DerivedKeyCapability.ready(TransitDerivedKeyProvider.PROVIDER_NAME));
        countingEncoder = new CountingEncoder(new ParProtoKeyprovAadV1Encoder());
        resultStore = new InMemoryOperationResultStore(clock);
        provider = new TransitDerivedKeyProvider(
                new DerivedKeyPolicyRegistry(),
                new DerivedKeyContextEncoder(),
                transitClient,
                new CertificatePublicKeyWrapper(),
                metadataCache,
                readiness,
                clock,
                EnvelopeAadEncoderRegistry.of(countingEncoder),
                resultStore,
                ParProtoKeyprovAadV1Encoder.PROFILE_ID,
                Duration.ofDays(30));
        transitClient.fixedResult = new byte[32];
        for (int i = 0; i < 32; i++) {
            transitClient.fixedResult[i] = (byte) i;
        }
    }

    private DerivedKeyCommand command(KeyPurpose purpose, ValidatedRecipientEvidence evidence) {
        return command("op-1", purpose, evidence);
    }

    private DerivedKeyCommand command(String operationId, KeyPurpose purpose,
                                      ValidatedRecipientEvidence evidence) {
        return new DerivedKeyCommand(BizType.V2C_COMM_ROOT, KeyAnchor.vin(VIN), purpose, evidence,
                DerivationContext.of("v1", 7L), new OperationContext(operationId, "idem-" + operationId));
    }

    /**
     * 构造未配置外部 AAD profile 的 legacy Provider（新 V2C ECDH-ES 必须 fail-closed）。
     */
    private TransitDerivedKeyProvider legacyProviderWithoutProfile(
            TransitDerivedKeyReadiness readiness) {
        return new TransitDerivedKeyProvider(
                new DerivedKeyPolicyRegistry(),
                new DerivedKeyContextEncoder(),
                transitClient,
                new CertificatePublicKeyWrapper(),
                metadataCache,
                readiness,
                clock);
    }

    @Test
    void deriveAndWrap_v2cUplink_fixedVectorAndUnwrap() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256EvidenceFrom(
                pki, "cert-001", WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        transitClient.fixedResult = CanonicalEncoding.sha256(
                ("openiov|v2c|v1|" + VIN + "|UPLINK_AEAD").getBytes(StandardCharsets.UTF_8));

        DerivedWrappedKey result = provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));

        // context 固定向量：Transit 收到 openiov|v2c|v1|VIN|UPLINK_AEAD
        assertArrayEquals(("openiov|v2c|v1|" + VIN + "|UPLINK_AEAD")
                        .getBytes(StandardCharsets.UTF_8), transitClient.lastHmacInput(),
                "Transit 输入必须为固定向量 context");
        // KCV = first_3(SHA-256(keyMaterial))
        assertArrayEquals(DerivedKeyKcv.first3Sha256(transitClient.fixedResult), result.kcv());
        // 信封可由模拟 TBOX SEC/HSM 解封出同一派生材料（自描述，外部 AAD profile 路径）
        byte[] unwrapped = ReferenceDerivedKeyUnwrapper.unwrapWithInfo(pki.leafKeyPair().getPrivate(),
                toEnvelope(result), "req-1", "V2C_COMM_ROOT");
        assertArrayEquals(transitClient.fixedResult, unwrapped);
        assertEquals(3, result.rootKeyVersion());
        assertNotNull(result.envelope());
        // CR-020：结构化 view 必须携带 aadProfileId 与外部 canonical AAD（加密前注入）
        EcdhEsP256EnvelopeViewV1 v = (EcdhEsP256EnvelopeViewV1) result.envelope();
        assertEquals(ParProtoKeyprovAadV1Encoder.PROFILE_ID, v.aadProfileId());
        assertArrayEquals(countingEncoder.lastEncoded, v.canonicalAad(),
                "AAD 必须是 encoder 加密前输出，禁止加密后替换");
        assertArrayEquals(CanonicalEncoding.sha256(v.canonicalAad()), v.aadDigest());
    }

    @Test
    void deriveAndWrap_externalAadProfile_boundToEnvelopeAndUnwrap() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256EvidenceFrom(
                pki, "cert-001", WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        DerivedWrappedKey result = provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));

        EcdhEsP256EnvelopeViewV1 v = (EcdhEsP256EnvelopeViewV1) result.envelope();
        assertEquals(ParProtoKeyprovAadV1Encoder.PROFILE_ID, v.aadProfileId());
        // 外部 AAD 参与 AES-GCM：解封必须使用同一 AAD 才能还原明文
        byte[] unwrapped = ReferenceDerivedKeyUnwrapper.unwrapWithInfo(pki.leafKeyPair().getPrivate(),
                toEnvelope(result), "req-1", "V2C_COMM_ROOT");
        assertArrayEquals(transitClient.fixedResult, unwrapped);
        // core digest 对含外部 AAD 的信封成立
        assertTrue(CanonicalEncoding.constantTimeEquals(v.coreEnvelopeDigest(),
                DerivedKeyEnvelopeCanonical.envelopeDigest(toEnvelope(result))));
    }

    @Test
    void deriveAndWrap_replay_sameOperation_returnsOriginalBytesWithoutReEncoding() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        DerivedWrappedKey first = provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));
        int hmacCallsAfterFirst = transitClient.hmacCalls;
        int encoderCallsAfterFirst = countingEncoder.calls;

        DerivedWrappedKey replay = provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));

        // 原字节重放：envelopeBytes / digest / KCV 完全一致
        assertArrayEquals(first.envelopeBytes(), replay.envelopeBytes(),
                "同 operation 重放必须返回原信封字节（FW-SEC-DSN-CR-020 §4）");
        assertArrayEquals(first.envelopeDigest(), replay.envelopeDigest());
        assertArrayEquals(first.kcv(), replay.kcv());
        // 重放不得再次调用 encoder/随机源/Transit（测试 5）
        assertEquals(hmacCallsAfterFirst, transitClient.hmacCalls,
                "重放不得再次调用 Transit");
        assertEquals(encoderCallsAfterFirst, countingEncoder.calls,
                "重放不得再次调用 encoder（不重新编码）");
    }

    @Test
    void deriveAndWrap_switchEncoderImplementation_originalBytesRetained() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        DerivedWrappedKey first = provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));

        // 切换 encoder 实现（不同输出）：同 operation 重放仍返回原字节（结果存储重放）
        TransitDerivedKeyReadiness readiness = mock(TransitDerivedKeyReadiness.class);
        when(readiness.capability())
                .thenReturn(DerivedKeyCapability.ready(TransitDerivedKeyProvider.PROVIDER_NAME));
        TransitDerivedKeyProvider upgraded = new TransitDerivedKeyProvider(
                new DerivedKeyPolicyRegistry(),
                new DerivedKeyContextEncoder(),
                transitClient,
                new CertificatePublicKeyWrapper(),
                metadataCache,
                readiness,
                clock,
                EnvelopeAadEncoderRegistry.of(new DifferentOutputEncoder()),
                resultStore,
                ParProtoKeyprovAadV1Encoder.PROFILE_ID,
                Duration.ofDays(30));

        DerivedWrappedKey replay = upgraded.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));
        assertArrayEquals(first.envelopeBytes(), replay.envelopeBytes(),
                "升级 encoder 实现后原 operation 仍返回原字节（测试 6）");
        assertEquals(ParProtoKeyprovAadV1Encoder.PROFILE_ID, replay.envelope().aadProfileId());
    }

    @Test
    void deriveAndWrap_sameOperationDifferentDigest_conflict() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));

        // 同 operationId 不同 purpose → 请求摘要（profile/hash）变化 → 幂等冲突
        assertThrows(DerivedWrapIdempotencyConflictException.class,
                () -> provider.deriveAndWrap(command(KeyPurpose.DOWNLINK_AEAD, evidence)));
    }

    @Test
    void deriveAndWrap_profileMissing_failClosed() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        TransitDerivedKeyReadiness readiness = mock(TransitDerivedKeyReadiness.class);
        when(readiness.capability())
                .thenReturn(DerivedKeyCapability.ready(TransitDerivedKeyProvider.PROVIDER_NAME));
        TransitDerivedKeyProvider legacy = legacyProviderWithoutProfile(readiness);

        TransitException ex = assertThrows(TransitException.class,
                () -> legacy.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence)));
        assertEquals(TransitReason.AAD_PROFILE_NOT_CONFIGURED, ex.transitReason(),
                "新 V2C ECDH-ES 未配置 aadProfileId 必须 fail-closed（CR-020 §6 收紧）");
        assertEquals(0, transitClient.hmacCalls, "未配置 profile 时不得调用 Transit");
    }

    @Test
    void deriveAndWrap_sameInput_sameKcvAndLogicalKeyId() throws Exception {
        transitClient.deterministicFromInput = true;
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        DerivedWrappedKey r1 = provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));
        DerivedWrappedKey r2 = provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));
        assertArrayEquals(r1.kcv(), r2.kcv());
        assertEquals(r1.logicalKeyId(), r2.logicalKeyId());
    }

    @Test
    void deriveAndWrap_differentPurpose_differentKcv() throws Exception {
        transitClient.deterministicFromInput = true;
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        DerivedWrappedKey up = provider.deriveAndWrap(command("op-1", KeyPurpose.UPLINK_AEAD, evidence));
        assertArrayEquals(("openiov|v2c|v1|" + VIN + "|UPLINK_AEAD")
                        .getBytes(StandardCharsets.UTF_8), transitClient.lastHmacInput(),
                "UPLINK context 固定向量");

        DerivedWrappedKey down = provider.deriveAndWrap(command("op-2", KeyPurpose.DOWNLINK_AEAD, evidence));
        assertArrayEquals(("openiov|v2c|v1|" + VIN + "|DOWNLINK_AEAD")
                        .getBytes(StandardCharsets.UTF_8), transitClient.lastHmacInput(),
                "DOWNLINK context 固定向量");
        assertTrue(!Arrays.equals(up.kcv(), down.kcv()),
                "不同 purpose 必须得到不同逻辑密钥/KCV（域隔离）");
    }

    @Test
    void deriveAndWrap_换证书_kcv不变wrappedKey变化() throws Exception {
        transitClient.deterministicFromInput = true;
        ValidatedRecipientEvidence e1 = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        TestPkiMaterial.Pki pki2 = TestPkiMaterial.generate();
        byte[] leafDer2 = pki2.leafCert().getEncoded();
        ValidatedRecipientEvidence e2 = new ValidatedRecipientEvidence(
                "cert-002", leafDer2, pki2.leafKeyPair().getPublic().getEncoded(),
                CanonicalEncoding.hexLower(CanonicalEncoding.sha256(leafDer2)),
                e1.certificateProfile(), e1.validatedWrapSuite(),
                e1.validatedAt(), e1.validUntil(),
                ValidatedRecipientEvidence.RecipientStatus.GOOD, "d2", "req-2");

        DerivedWrappedKey r1 = provider.deriveAndWrap(command("op-1", KeyPurpose.UPLINK_AEAD, e1));
        DerivedWrappedKey r2 = provider.deriveAndWrap(command("op-2", KeyPurpose.UPLINK_AEAD, e2));

        // 换件/换证书：逻辑密钥与 KCV 不变，Wrapped Key 变化（随机化封装）
        assertArrayEquals(r1.kcv(), r2.kcv());
        assertEquals(r1.logicalKeyId(), r2.logicalKeyId());
        assertTrue(!Arrays.equals(r1.envelopeBytes(), r2.envelopeBytes()));
    }

    @Test
    void deriveAndWrap_expiredEvidence_rejectedBeforeTransit() throws Exception {
        ValidatedRecipientEvidence evidence = new ValidatedRecipientEvidence(
                "cert-001", new byte[]{1}, new byte[]{2}, "aa".repeat(32),
                null, WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                clock.instant().minusSeconds(7200), clock.instant().minusSeconds(3600),
                ValidatedRecipientEvidence.RecipientStatus.GOOD, "d", "req");
        TransitException ex = assertThrows(TransitException.class,
                () -> provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence)));
        assertEquals(TransitReason.RECIPIENT_CERTIFICATE_INVALID, ex.transitReason());
        assertEquals(0, transitClient.hmacCalls, "证书门禁失败时 Transit 调用必须为 0");
    }

    @Test
    void deriveAndWrap_emptySpki_rejectedBeforeTransit() throws Exception {
        ValidatedRecipientEvidence evidence = new ValidatedRecipientEvidence(
                "cert-001", new byte[]{1}, new byte[0], "aa".repeat(32),
                null, WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM,
                clock.instant(), clock.instant().plusSeconds(3600),
                ValidatedRecipientEvidence.RecipientStatus.GOOD, "d", "req");
        assertThrows(TransitException.class,
                () -> provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence)));
        assertEquals(0, transitClient.hmacCalls);
    }

    @Test
    void deriveAndWrap_wrongCurveOrSuite_rejectedBeforeTransit() throws Exception {
        // EC 套件 + 非 P-256 曲线（secp384r1）：最终门禁拒绝，Transit 调用为 0
        ValidatedRecipientEvidence wrongCurve = ValidatedRecipientEvidenceFixtures.curveEvidence(
                "secp384r1", WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        TransitException ex = assertThrows(TransitException.class,
                () -> provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, wrongCurve)));
        assertEquals(TransitReason.RECIPIENT_CERTIFICATE_INVALID, ex.transitReason());
        assertEquals(0, transitClient.hmacCalls);

        // RSA 套件 + V2C 策略（只允许 ECDH-ES）：策略校验拒绝（DERIVATION_POLICY_INVALID）
        ValidatedRecipientEvidence rsaSuite = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.RSA_OAEP_SHA256);
        TransitException policyEx = assertThrows(TransitException.class,
                () -> provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, rsaSuite)));
        assertEquals(TransitReason.DERIVATION_POLICY_INVALID, policyEx.transitReason());
        assertEquals(0, transitClient.hmacCalls);
    }

    @Test
    void deriveAndWrap_transitFailure_propagates() throws Exception {
        transitClient.failure = TransitException.sealed("hmac:v2c-comm-root");
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        TransitException ex = assertThrows(TransitException.class,
                () -> provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence)));
        assertEquals(TransitReason.TRANSIT_SEALED, ex.transitReason());
    }

    @Test
    void deriveAndWrap_keyMaterialLengthInvalid_failClosed() throws Exception {
        transitClient.fixedResult = new byte[16];
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        TransitException ex = assertThrows(TransitException.class,
                () -> provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence)));
        assertEquals(TransitReason.DERIVED_KEY_LENGTH_INVALID, ex.transitReason());
    }

    @Test
    void deriveAndWrap_contextBuffer_zeroizedInFinally() throws Exception {
        ValidatedRecipientEvidence evidence = ValidatedRecipientEvidenceFixtures.p256Evidence(
                WrappingSuite.ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        provider.deriveAndWrap(command(KeyPurpose.UPLINK_AEAD, evidence));
        byte[] captured = transitClient.lastHmacInputRaw();
        assertNotNull(captured);
        for (byte b : captured) {
            assertEquals((byte) 0, b, "派生 context 缓冲必须在 finally 清零");
        }
    }

    /**
     * 由结构化只读视图重建 canonical 信封（测试范围：供参考解封器使用；生产不解析 view→envelope）。
     */
    private static DerivedWrappedKeyEnvelopeV1 toEnvelope(DerivedWrappedKey result) {
        EcdhEsP256EnvelopeViewV1 v = (EcdhEsP256EnvelopeViewV1) result.envelope();
        return new DerivedWrappedKeyEnvelopeV1(
                DerivedWrappedKeyEnvelopeV1.V1, v.wrappingSuite(),
                v.serverEphemeralPublicKey(), v.hkdfSalt(), v.hkdfContextVersion(),
                v.nonce(), v.ciphertext(), v.authenticationTag(),
                v.canonicalAad(), v.aadDigest(),
                CanonicalEncoding.hexLower(v.recipientCertificateDigest()),
                v.logicalKeyId(), v.purpose(), v.businessKeyVersion(), v.rootKeyVersion(),
                v.derivationVersion(), v.keyCheckValue(), v.operationId(), v.envelopeDigest());
    }

    /**
     * 计数 encoder：记录调用次数与最后输出（验证重放不再次调用）。
     */
    static final class CountingEncoder implements EnvelopeAadEncoder {
        private final EnvelopeAadEncoder delegate;
        int calls;
        byte[] lastEncoded;

        CountingEncoder(EnvelopeAadEncoder delegate) {
            this.delegate = delegate;
        }

        @Override
        public String profileId() {
            return delegate.profileId();
        }

        @Override
        public byte[] encode(EnvelopeAadContext context) {
            calls++;
            lastEncoded = delegate.encode(context);
            return lastEncoded.clone();
        }
    }

    /**
     * 切换实现测试用 encoder：profile 相同但输出不同（确定性）。
     */
    static final class DifferentOutputEncoder extends ParProtoKeyprovAadV1Encoder {
        @Override
        public byte[] encode(EnvelopeAadContext context) {
            byte[] base = super.encode(context);
            byte[] out = new byte[base.length + 4];
            out[0] = 0x01;
            out[1] = 0x02;
            out[2] = 0x03;
            out[3] = 0x04;
            System.arraycopy(base, 0, out, 4, base.length);
            return out;
        }
    }

    /**
     * 可控 Transit 客户端：记录输入、可注入失败；HMAC 材料可固定或由输入确定性派生。
     */
    static final class FakeTransitHmacClient implements TransitHmacClient {
        byte[] fixedResult;
        boolean deterministicFromInput;
        TransitException failure;
        int hmacCalls;
        byte[] lastInputSnapshot;
        byte[] lastInputRaw;

        @Override
        public TransitHmacResult hmac(String approvedKeyName, String algorithm, byte[] input,
                                      OperationContext operation) {
            hmacCalls++;
            lastInputSnapshot = input == null ? null : input.clone();
            lastInputRaw = input;
            if (failure != null) {
                throw failure;
            }
            byte[] result = deterministicFromInput
                    ? CanonicalEncoding.sha256(input) : fixedResult;
            return new TransitHmacResult("v1", result, approvedKeyName);
        }

        @Override
        public TransitKeyMetadata readMetadata(String approvedKeyName) {
            return new TransitKeyMetadata("v2c-comm-root", "aes256-gcm96", false, true, 3, 3, 1);
        }

        @Override
        public TransitSystemHealth probeHealth() {
            return new TransitSystemHealth(true, false, false);
        }

        byte[] lastHmacInput() {
            return lastInputSnapshot;
        }

        byte[] lastHmacInputRaw() {
            return lastInputRaw;
        }
    }
}
