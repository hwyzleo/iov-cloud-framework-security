package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateApplicationRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateNotReadyException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * StepCaPkiClient 单元测试（FW-SEC-DSN-CR-008 §3/§5/§6/§9）
 */
class StepCaPkiClientTest {

    private TestPkiMaterial.Pki material;
    private StepCaApiClient apiClient;
    private StepCaTokenProvider tokenProvider;
    private CryptoMetrics metrics;
    private InMemoryCertificateEnrollmentResultStore store;
    private StepCaProfilePolicyRegistry registry;
    private StepCaPkiClient client;
    private String rootFingerprint;

    @BeforeEach
    void setUp() throws Exception {
        material = TestPkiMaterial.generate(true, "TBOX-00000000000000000000000000000001");
        rootFingerprint = EnrollmentRecord.fingerprintHex(material.rootCert().getEncoded());

        apiClient = mock(StepCaApiClient.class);
        tokenProvider = mock(StepCaTokenProvider.class);
        metrics = mock(CryptoMetrics.class);
        store = new InMemoryCertificateEnrollmentResultStore(Duration.ofMinutes(30), 100);
        registry = new StepCaProfilePolicyRegistry(Map.of(
                "TBOX_IDENTITY", new StepCaProfilePolicy(
                        "TBOX_IDENTITY", "openiov", "kid-1", Duration.ofDays(365),
                        List.of("EC_P256"), List.of("CLIENT_AUTH"), "TBOX")));
        EnrollmentIdempotencyService idempotency = new EnrollmentIdempotencyService(store);

        client = new StepCaPkiClient(apiClient, tokenProvider, registry, store,
                new CertificateChainValidator(), idempotency, metrics,
                URI.create("https://step-ca:9000"), rootFingerprint);

        when(tokenProvider.createToken(any())).thenReturn("mock-ott");
        when(apiClient.sign(any())).thenReturn(new StepCaApiClient.StepCaSignResponse(
                TestPkiMaterial.pem("CERTIFICATE", material.leafCert().getEncoded()),
                List.of(
                        TestPkiMaterial.pem("CERTIFICATE", material.intermediateCert().getEncoded()),
                        TestPkiMaterial.pem("CERTIFICATE", material.rootCert().getEncoded()))));
    }

    private PkiClient.ApplyCommand command(String requestId, String idemKey) {
        return new PkiClient.ApplyCommand(requestId, "TBOX_IDENTITY", "TBOX_IDENTITY",
                material.csrPem(), "TBOX-00000000000000000000000000000001", idemKey,
                Map.of("caller", "vmd"));
    }

    @Test
    void submit_shouldIssueSynchronously_andPersist() throws Exception {
        PkiClient.ApplyResponse response = client.submit(command("req-1", "idem-1"));

        assertEquals("req-1", response.requestId());
        assertEquals("ISSUED", response.state());

        EnrollmentRecord record = store.findByRequestId("req-1").orElseThrow();
        assertEquals(EnrollmentState.ISSUED, record.state());
        assertEquals("vmd", record.caller());
        assertArrayEquals(material.leafCert().getEncoded(), record.leafCertificate());
        assertEquals(2, record.certificateChain().size());
        assertNotNull(record.serialNumber());
        assertNotNull(record.sha256Fingerprint());
        // 幂等索引
        assertEquals("req-1", store.findByIdempotency("vmd", "idem-1").orElseThrow().requestId());
        verify(metrics).recordEnrollmentOutcome("step-ca", "issued");
    }

    @Test
    void submit_shouldBuildTokenRequest_withPinnedRootAndSans() {
        client.submit(command("req-1", "idem-1"));

        verify(tokenProvider).createToken(argThat(request -> {
            assertEquals("req-1", request.requestId());
            assertEquals("openiov", request.provisioner());
            assertEquals("kid-1", request.kid());
            assertEquals(URI.create("https://step-ca:9000/1.0/sign"), request.audience());
            assertEquals("TBOX-00000000000000000000000000000001", request.subject());
            assertEquals(List.of("TBOX-00000000000000000000000000000001"), request.sans());
            assertEquals(rootFingerprint, request.rootSha256());
            return true;
        }));
    }

    @Test
    void submit_shouldMarkRejected_on4xx() {
        when(apiClient.sign(any())).thenThrow(
                new CertificateApplicationRejectedException("provisioner token invalid"));

        assertThrows(CertificateApplicationRejectedException.class,
                () -> client.submit(command("req-2", "idem-2")));

        EnrollmentRecord record = store.findByRequestId("req-2").orElseThrow();
        assertEquals(EnrollmentState.REJECTED, record.state());
        assertNotNull(record.errorSummary());
        verify(metrics).recordEnrollmentOutcome("step-ca", "rejected");
    }

    @Test
    void submit_shouldMarkUnknown_whenOutcomeUnknown() {
        when(apiClient.sign(any())).thenThrow(
                new PkiOutcomeUnknownException("request sent but response lost"));

        assertThrows(PkiOutcomeUnknownException.class,
                () -> client.submit(command("req-3", "idem-3")));

        EnrollmentRecord record = store.findByRequestId("req-3").orElseThrow();
        assertEquals(EnrollmentState.UNKNOWN, record.state());
        verify(metrics).recordEnrollmentOutcome("step-ca", "unknown");
    }

    @Test
    void submit_shouldMarkFailed_whenChainValidationFails() throws Exception {
        // 篡改签发响应：叶子公钥与 CSR 不一致
        java.security.KeyPair otherKeyPair = TestPkiMaterial.generateKeyPair();
        java.security.cert.X509Certificate forgedLeaf = TestPkiMaterial.issueLeaf(
                TestPkiMaterial.INTERMEDIATE_SUBJECT, material.intermediateKeyPair(),
                TestPkiMaterial.LEAF_SUBJECT, otherKeyPair.getPublic(),
                java.math.BigInteger.valueOf(77), true, "TBOX-00000000000000000000000000000001");
        when(apiClient.sign(any())).thenReturn(new StepCaApiClient.StepCaSignResponse(
                TestPkiMaterial.pem("CERTIFICATE", forgedLeaf.getEncoded()),
                List.of(
                        TestPkiMaterial.pem("CERTIFICATE", material.intermediateCert().getEncoded()),
                        TestPkiMaterial.pem("CERTIFICATE", material.rootCert().getEncoded()))));

        assertThrows(Exception.class,
                () -> client.submit(command("req-4", "idem-4")));

        assertEquals(EnrollmentState.FAILED,
                store.findByRequestId("req-4").orElseThrow().state());
        verify(metrics).recordEnrollmentOutcome("step-ca", "failed");
    }

    @Test
    void submit_shouldNotReSign_forSameIdempotencyKey() {
        client.submit(command("req-1", "idem-1"));

        PkiClient.ApplyResponse second = client.submit(command("req-1", "idem-1"));

        assertEquals("req-1", second.requestId());
        assertEquals("ISSUED", second.state());
        verify(apiClient, times(1)).sign(any());
    }

    @Test
    void submit_shouldResign_whenPreviousFailed() throws Exception {
        // 第一次：签发响应证书被篡改 → framework 校验失败 → FAILED（未产生证书）
        java.security.KeyPair otherKeyPair = TestPkiMaterial.generateKeyPair();
        java.security.cert.X509Certificate forgedLeaf = TestPkiMaterial.issueLeaf(
                TestPkiMaterial.INTERMEDIATE_SUBJECT, material.intermediateKeyPair(),
                TestPkiMaterial.LEAF_SUBJECT, otherKeyPair.getPublic(),
                java.math.BigInteger.valueOf(77), true, "TBOX-00000000000000000000000000000001");
        when(apiClient.sign(any())).thenReturn(new StepCaApiClient.StepCaSignResponse(
                TestPkiMaterial.pem("CERTIFICATE", forgedLeaf.getEncoded()),
                List.of(
                        TestPkiMaterial.pem("CERTIFICATE", material.intermediateCert().getEncoded()),
                        TestPkiMaterial.pem("CERTIFICATE", material.rootCert().getEncoded()))));
        assertThrows(Exception.class, () -> client.submit(command("req-f1", "idem-f1")));
        assertEquals(EnrollmentState.FAILED,
                store.findByRequestId("req-f1").orElseThrow().state());

        // 第二次：恢复后同 key 重签 → 新 requestId + ISSUED
        when(apiClient.sign(any())).thenReturn(new StepCaApiClient.StepCaSignResponse(
                TestPkiMaterial.pem("CERTIFICATE", material.leafCert().getEncoded()),
                List.of(
                        TestPkiMaterial.pem("CERTIFICATE", material.intermediateCert().getEncoded()),
                        TestPkiMaterial.pem("CERTIFICATE", material.rootCert().getEncoded()))));
        PkiClient.ApplyResponse retry = client.submit(command("req-f2", "idem-f1"));

        assertEquals("ISSUED", retry.state());
        assertNotEquals("req-f1", retry.requestId(), "重签应使用新 requestId");
        verify(apiClient, times(2)).sign(any());
        // 幂等索引指向新记录；旧 FAILED 记录保留（审计）
        assertEquals(retry.requestId(),
                store.findByIdempotency("vmd", "idem-f1").orElseThrow().requestId());
        assertTrue(store.findByRequestId("req-f1").isPresent());
    }

    @Test
    void submit_shouldResign_whenPreviousRejected() {
        // Given — 预置 REJECTED 终态记录（CA 拒绝，未产生证书）
        byte[] csr = material.csrPem();
        store.createSubmitting("req-r1", "vmd", "idem-r1", csr,
                EnrollmentRecord.sha256Hex(csr), "TBOX_IDENTITY");
        store.markTerminal("req-r1", EnrollmentState.REJECTED, "rejected by CA");

        // When — 失败可重试：同 key 重签（apiClient 使用 setUp 默认有效响应）
        PkiClient.ApplyResponse retry = client.submit(command("req-r2", "idem-r1"));

        // Then
        assertEquals("ISSUED", retry.state());
        assertNotEquals("req-r1", retry.requestId(), "重签应使用新 requestId");
        verify(apiClient, times(1)).sign(any());
        assertEquals(retry.requestId(),
                store.findByIdempotency("vmd", "idem-r1").orElseThrow().requestId());
        assertTrue(store.findByRequestId("req-r1").isPresent(), "旧 REJECTED 记录保留");
    }

    @Test
    void submit_shouldNotResign_whenPreviousUnknown() {
        // 第一次：结果未知 → UNKNOWN
        when(apiClient.sign(any())).thenThrow(
                new PkiOutcomeUnknownException("request sent but response lost"));
        assertThrows(PkiOutcomeUnknownException.class,
                () -> client.submit(command("req-u1", "idem-u1")));
        assertEquals(EnrollmentState.UNKNOWN,
                store.findByRequestId("req-u1").orElseThrow().state());

        // 第二次：同 key 返回 UNKNOWN，禁止自动重签
        PkiClient.ApplyResponse second = client.submit(command("req-u2", "idem-u1"));
        assertEquals("UNKNOWN", second.state());
        assertEquals("req-u1", second.requestId());
        verify(apiClient, times(1)).sign(any());
    }

    @Test
    void submit_shouldThrowConflict_forSameKeyDifferentParams() {
        client.submit(command("req-1", "idem-1"));
        byte[] differentCsr = ("-----BEGIN CERTIFICATE REQUEST-----\ndiff\n-----END CERTIFICATE REQUEST-----")
                .getBytes(StandardCharsets.UTF_8);
        PkiClient.ApplyCommand conflict = new PkiClient.ApplyCommand(
                "req-x", "TBOX_IDENTITY", "TBOX_IDENTITY", differentCsr,
                "TBOX-00000000000000000000000000000001", "idem-1", Map.of("caller", "vmd"));

        assertThrows(net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateIdempotencyConflictException.class,
                () -> client.submit(conflict));
        verify(apiClient, times(1)).sign(any());
    }

    @Test
    void getStatus_shouldReadFromResultStore() {
        client.submit(command("req-1", "idem-1"));

        PkiClient.StatusResponse status = client.getStatus("req-1");
        assertEquals("ISSUED", status.state());
    }

    @Test
    void getStatus_shouldThrow_whenNoRecord() {
        assertThrows(PkiDependencyUnavailableException.class, () -> client.getStatus("unknown"));
    }

    @Test
    void getCertificate_shouldReturnIssuedMaterial() throws Exception {
        client.submit(command("req-1", "idem-1"));

        PkiClient.CertificateResponse response = client.getCertificate("req-1");
        assertArrayEquals(material.leafCert().getEncoded(), response.leafCertificate());
        assertNotNull(response.certificateChain());
        assertNotNull(response.serialNumber());
        assertNotNull(response.notBefore());
        assertNotNull(response.notAfter());
    }

    @Test
    void getCertificate_shouldThrowNotReady_whenNotIssued() {
        when(apiClient.sign(any())).thenThrow(
                new CertificateApplicationRejectedException("rejected by CA"));
        assertThrows(CertificateApplicationRejectedException.class,
                () -> client.submit(command("req-2", "idem-2"))); // REJECTED
        assertThrows(CertificateNotReadyException.class, () -> client.getCertificate("req-2"));
    }

    @Test
    void queryCertificate_shouldBeUnsupported() {
        assertThrows(PkiDependencyUnavailableException.class,
                () -> client.queryCertificate("serial-1"));
    }

    @Test
    void managesResultStore_shouldBeTrue() {
        assertTrue(client.managesResultStore());
    }
}
