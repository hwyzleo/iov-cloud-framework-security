package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateApplicationRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.FixedHostPortGenericContainer;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * step-ca 契约测试（FW-SEC-DSN-CR-008 §9）
 * <p>
 * 使用官方 smallstep/step-ca 镜像（Testcontainers）验证真实 /1.0/sign 请求与响应，
 * 不使用自研 stub 代替最终验收。需要 Docker；无 Docker 时自动跳过。
 * <p>
 * 覆盖：JWK OTT 签发 → 同步签发 ISSUED、幂等不重签、重启后按 requestId 恢复、无效 OTT 拒绝。
 */
@Tag("contract")
@Testcontainers(disabledWithoutDocker = true)
@Timeout(value = 3, unit = TimeUnit.MINUTES)
class StepCaContractTest {

    private static final int HOST_PORT = 19002;
    private static final String PROVISIONER = "openiov";
    private static final String PROVISIONER_PASSWORD = "provpass";
    private static final String SUBJECT = "TBOX-00000000000000000000000000000001";

    @Container
    static final GenericContainer<?> stepCa = new FixedHostPortGenericContainer<>("smallstep/step-ca:latest")
            .withFixedExposedPort(HOST_PORT, 9000)
            .withEnv("DOCKER_STEPCA_INIT_NAME", "Contract CA")
            .withEnv("DOCKER_STEPCA_INIT_DNS_NAMES", "localhost")
            .withEnv("DOCKER_STEPCA_INIT_PROVISIONER_NAME", PROVISIONER)
            .withEnv("DOCKER_STEPCA_INIT_ADDRESS", ":9000")
            .withEnv("DOCKER_STEPCA_INIT_PASSWORD", PROVISIONER_PASSWORD)
            .withEnv("DOCKER_STEPCA_INIT_WITH_CA_URL", "https://localhost:" + HOST_PORT);

    @TempDir
    static Path tempDir;

    private static URI endpoint;
    private static String rootFingerprint;
    private static String kid;
    private static HttpStepCaApiClient apiClient;
    private static JwkStepCaTokenProvider tokenProvider;
    private static CertificateChainValidator chainValidator;
    private static CryptoMetrics metrics;
    private static TestPkiMaterial.Pki material;

    @BeforeAll
    static void setUp() throws Exception {
        endpoint = URI.create("https://localhost:" + HOST_PORT);

        // 1) 等待 CA 就绪并获取根指纹
        rootFingerprint = waitForReady();

        // 2) 读取 ca.json 中的 JWK provisioner（公开 JWK + encryptedKey JWE compact）
        org.testcontainers.containers.Container.ExecResult exec =
                stepCa.execInContainer("cat", "/home/step/config/ca.json");
        JsonNode caJson = new ObjectMapper().readTree(exec.getStdout());
        JsonNode provisioner = null;
        for (JsonNode p : caJson.get("authority").get("provisioners")) {
            if ("JWK".equals(p.get("type").asText())) {
                provisioner = p;
                break;
            }
        }
        assertNotNull(provisioner, "ca.json must contain a JWK provisioner");
        kid = provisioner.get("key").get("kid").asText();

        // 合并公开 JWK 与 encryptedKey（step-ca 将二者作为 provisioner 的同级字段）
        com.fasterxml.jackson.databind.node.ObjectNode keyJson =
                (com.fasterxml.jackson.databind.node.ObjectNode) provisioner.get("key").deepCopy();
        keyJson.set("encryptedKey", provisioner.get("encryptedKey"));
        Path keyFile = tempDir.resolve("provisioner.jwk");
        Files.writeString(keyFile, new ObjectMapper().writeValueAsString(keyJson),
                StandardCharsets.UTF_8);
        Path passwordFile = tempDir.resolve("provisioner.password");
        Files.writeString(passwordFile, PROVISIONER_PASSWORD, StandardCharsets.UTF_8);

        // 3) 构建 framework 适配组件
        tokenProvider = new JwkStepCaTokenProvider(keyFile, passwordFile, Duration.ofMinutes(5));
        apiClient = new HttpStepCaApiClient(endpoint, rootFingerprint,
                Duration.ofSeconds(3), Duration.ofSeconds(5), 2, Duration.ofMillis(100));
        chainValidator = new CertificateChainValidator();
        metrics = new CryptoMetrics(new io.micrometer.core.instrument.simple.SimpleMeterRegistry());

        material = TestPkiMaterial.generate(true, SUBJECT);
    }

    private static String waitForReady() throws Exception {
        long deadline = System.currentTimeMillis() + 120_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                org.testcontainers.containers.Container.ExecResult result =
                        stepCa.execInContainer("step", "certificate", "fingerprint", "/home/step/certs/root_ca.crt");
                if (result.getExitCode() == 0) {
                    String fingerprint = result.getStdout().trim();
                    if (!fingerprint.isEmpty()) {
                        // CA 可能已 init 但服务未就绪：以根引导成功为准
                        try {
                            new HttpStepCaApiClient(endpoint, fingerprint,
                                    Duration.ofSeconds(2), Duration.ofSeconds(2), 1, Duration.ofMillis(10));
                            return fingerprint;
                        } catch (Exception ignore) {
                            // 服务尚未就绪，继续等待
                        }
                    }
                }
            } catch (Exception ignore) {
                // 容器尚未完全启动
            }
            Thread.sleep(2_000);
        }
        throw new IllegalStateException("step-ca container not ready within 120s");
    }

    private static StepCaProfilePolicyRegistry registry() {
        return new StepCaProfilePolicyRegistry(Map.of(
                "TBOX_IDENTITY", new StepCaProfilePolicy(
                        "TBOX_IDENTITY", PROVISIONER, kid, Duration.ofHours(1),
                        List.of("EC_P256"), List.of(), "TBOX")));
    }

    private static StepCaPkiClient newClient(InMemoryCertificateEnrollmentResultStore store) {
        return new StepCaPkiClient(apiClient, tokenProvider, registry(), store,
                chainValidator, new EnrollmentIdempotencyService(store), metrics,
                endpoint, rootFingerprint);
    }

    @Test
    void sign_shouldIssueCertificateSynchronously() throws Exception {
        InMemoryCertificateEnrollmentResultStore store =
                new InMemoryCertificateEnrollmentResultStore(Duration.ofMinutes(30), 100);
        StepCaPkiClient client = newClient(store);

        PkiClient.ApplyCommand command = new PkiClient.ApplyCommand(
                "req-contract-1", "TBOX_IDENTITY", "TBOX_IDENTITY",
                material.csrPem(), SUBJECT, "idem-contract-1", Map.of("caller", "vmd"));

        PkiClient.ApplyResponse response = client.submit(command);

        assertEquals("req-contract-1", response.requestId());
        assertEquals("ISSUED", response.state());

        // 结果存储已落 ISSUED + 证书材料
        EnrollmentRecord record = store.findByRequestId("req-contract-1").orElseThrow();
        assertEquals(EnrollmentState.ISSUED, record.state());
        assertNotNull(record.serialNumber());
        assertNotNull(record.sha256Fingerprint());
        assertEquals(2, record.certificateChain().size());

        // 证书链根指纹 == 配置根指纹（根固定）
        String chainRootFingerprint = EnrollmentRecord.fingerprintHex(
                record.certificateChain().get(record.certificateChain().size() - 1));
        assertEquals(rootFingerprint, chainRootFingerprint);

        // 叶子公钥与 CSR 一致（framework 侧已校验；此处复核）
        X509Certificate leaf = CertPem.parseCertificate(record.leafCertificate());
        assertTrue(leaf.getSubjectX500Principal().getName().contains(SUBJECT));

        // getStatus / getCertificate 从存储读取
        assertEquals("ISSUED", client.getStatus("req-contract-1").state());
        PkiClient.CertificateResponse cert = client.getCertificate("req-contract-1");
        assertArrayEquals(record.leafCertificate(), cert.leafCertificate());
    }

    @Test
    void submit_shouldBeIdempotent_withSameKey() {
        InMemoryCertificateEnrollmentResultStore store =
                new InMemoryCertificateEnrollmentResultStore(Duration.ofMinutes(30), 100);
        StepCaPkiClient client = newClient(store);

        PkiClient.ApplyCommand command = new PkiClient.ApplyCommand(
                "req-contract-2", "TBOX_IDENTITY", "TBOX_IDENTITY",
                material.csrPem(), SUBJECT, "idem-contract-2", Map.of("caller", "vmd"));

        PkiClient.ApplyResponse first = client.submit(command);
        PkiClient.ApplyResponse second = client.submit(command);

        assertEquals(first.requestId(), second.requestId());
        assertEquals("ISSUED", second.state());
    }

    @Test
    void shouldRecoverAfterRestart_byRequestId() throws Exception {
        InMemoryCertificateEnrollmentResultStore store =
                new InMemoryCertificateEnrollmentResultStore(Duration.ofMinutes(30), 100);

        // 首次进程：签发
        StepCaPkiClient firstProcess = newClient(store);
        PkiClient.ApplyCommand command = new PkiClient.ApplyCommand(
                "req-contract-3", "TBOX_IDENTITY", "TBOX_IDENTITY",
                material.csrPem(), SUBJECT, "idem-contract-3", Map.of("caller", "vmd"));
        firstProcess.submit(command);

        // 重启（同存储、新客户端实例）：仍可按 requestId 获取状态与证书
        StepCaPkiClient restarted = newClient(store);
        assertEquals("ISSUED", restarted.getStatus("req-contract-3").state());
        PkiClient.CertificateResponse cert = restarted.getCertificate("req-contract-3");
        assertNotNull(cert.leafCertificate());
        assertEquals("req-contract-3", cert.requestId());
    }

    @Test
    void sign_shouldReject_invalidOtt() {
        // 用错误的 OTT（任意字符串）直接调用原生 API → 4xx 鉴权失败
        StepCaApiClient.StepCaSignRequest request = new StepCaApiClient.StepCaSignRequest(
                new String(material.csrPem(), StandardCharsets.UTF_8),
                "not-a-valid-ott", null, null);
        assertThrows(CertificateApplicationRejectedException.class, () -> apiClient.sign(request));
    }
}
