package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.PkiClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateNotReadyException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CertificateProfileNotAllowedException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyRequest;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertApplyResult;
import net.hwyz.iov.cloud.framework.security.crypto.model.CertificateProfile;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnrollmentState;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import net.hwyz.iov.cloud.framework.security.crypto.model.SubjectRef;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * DefaultCertEnrollmentTemplate 单元测试
 * <p>
 * 使用 BouncyCastle 生成真实 PKI 材料（Root CA → Intermediate CA → Leaf / CSR），
 * 覆盖证书链解析、叶子证书与链的一致性、链内顺序及 CSR 公钥一致性校验。
 */
class DefaultCertEnrollmentTemplateTest {

    private static final X500Name ROOT_SUBJECT = new X500Name("CN=IOV Test Root CA");
    private static final X500Name INTERMEDIATE_SUBJECT = new X500Name("CN=IOV Test Intermediate CA");
    private static final X500Name LEAF_SUBJECT = new X500Name("CN=test-service");

    @Mock
    private PkiClient pkiClient;

    @Mock
    private CryptoMetrics cryptoMetrics;

    private DefaultCertEnrollmentTemplate template;

    private CertificateProfile allowedProfile;

    private CertificateProfile disallowedProfile;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        allowedProfile = new CertificateProfile(
                "SERVICE_MTLS",
                "pki-service-mtls",
                CertificateProfile.SubjectType.SERVICE,
                "RSA",
                "服务 mTLS 证书"
        );

        disallowedProfile = new CertificateProfile(
                "UNKNOWN_PROFILE",
                "pki-unknown",
                CertificateProfile.SubjectType.SERVICE,
                "RSA",
                "未知证书"
        );

        template = new DefaultCertEnrollmentTemplate(
                pkiClient,
                cryptoMetrics,
                List.of(allowedProfile)
        );
    }

    // ==================== apply / getStatus 基础行为 ====================

    @Test
    void apply_shouldSucceed_withValidRequest() {
        // Given
        byte[] csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBPjCB...\n-----END CERTIFICATE REQUEST-----".getBytes();
        SubjectRef subject = new SubjectRef(SubjectRef.SubjectType.CN, "test-service");
        CertApplyRequest request = new CertApplyRequest(
                allowedProfile, csr, subject, "idempotency-key-1", Map.of()
        );

        PkiClient.ApplyResponse pkiResponse = new PkiClient.ApplyResponse(
                "request-123", "PENDING", "Submitted"
        );
        when(pkiClient.submit(any())).thenReturn(pkiResponse);

        // When
        CertApplyResult result = template.apply(request);

        // Then
        assertNotNull(result);
        assertEquals("request-123", result.requestId());
        assertEquals(EnrollmentState.PENDING, result.state());
        verify(pkiClient).submit(any());
        verify(cryptoMetrics).recordCertificateEnrollment(anyLong());
    }

    @Test
    void apply_shouldThrowException_withDisallowedProfile() {
        // Given
        byte[] csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBPjCB...\n-----END CERTIFICATE REQUEST-----".getBytes();
        SubjectRef subject = new SubjectRef(SubjectRef.SubjectType.CN, "test-service");
        CertApplyRequest request = new CertApplyRequest(
                disallowedProfile, csr, subject, "idempotency-key-2", Map.of()
        );

        // When & Then
        assertThrows(CertificateProfileNotAllowedException.class, () -> template.apply(request));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void apply_shouldThrowException_withEmptyCsr() {
        // Given
        byte[] csr = new byte[0];
        SubjectRef subject = new SubjectRef(SubjectRef.SubjectType.CN, "test-service");
        CertApplyRequest request = new CertApplyRequest(
                allowedProfile, csr, subject, "idempotency-key-3", Map.of()
        );

        // When & Then
        assertThrows(InvalidCertificateRequestException.class, () -> template.apply(request));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void apply_shouldReturnExistingRequestId_forDuplicateIdempotencyKey() {
        // Given
        byte[] csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBPjCB...\n-----END CERTIFICATE REQUEST-----".getBytes();
        SubjectRef subject = new SubjectRef(SubjectRef.SubjectType.CN, "test-service");
        CertApplyRequest request1 = new CertApplyRequest(
                allowedProfile, csr, subject, "idempotency-key-4", Map.of()
        );
        CertApplyRequest request2 = new CertApplyRequest(
                allowedProfile, csr, subject, "idempotency-key-4", Map.of()
        );

        PkiClient.ApplyResponse pkiResponse = new PkiClient.ApplyResponse(
                "request-456", "PENDING", "Submitted"
        );
        when(pkiClient.submit(any())).thenReturn(pkiResponse);

        PkiClient.StatusResponse statusResponse = new PkiClient.StatusResponse(
                "request-456", "PENDING", "Processing"
        );
        when(pkiClient.getStatus("request-456")).thenReturn(statusResponse);

        // When
        template.apply(request1);
        CertApplyResult result2 = template.apply(request2);

        // Then
        assertEquals("request-456", result2.requestId());
        verify(pkiClient, times(1)).submit(any());
    }

    @Test
    void getStatus_shouldReturnCurrentState() {
        // Given
        PkiClient.StatusResponse statusResponse = new PkiClient.StatusResponse(
                "request-789", "ISSUED", "Certificate issued"
        );
        when(pkiClient.getStatus("request-789")).thenReturn(statusResponse);

        // When
        CertApplyResult result = template.getStatus("request-789");

        // Then
        assertNotNull(result);
        assertEquals("request-789", result.requestId());
        assertEquals(EnrollmentState.ISSUED, result.state());
        verify(cryptoMetrics).recordCertificateEnrollmentQuery(anyLong());
    }

    // ==================== getCertificate 一致性校验 ====================

    @Test
    void getCertificate_shouldReturnIssuedCertificate_withConsistentChain() throws Exception {
        // Given
        PkiMaterial material = generatePkiMaterial();
        String requestId = applyCsr(material, "idem-500");

        when(pkiClient.getStatus(requestId)).thenReturn(
                new PkiClient.StatusResponse(requestId, "ISSUED", "Issued"));
        when(pkiClient.getCertificate(requestId)).thenReturn(
                certificateResponse(requestId, material.leafCert.getEncoded(), material.chainPem,
                        material.leafCert.getSerialNumber().toString()));

        // When
        IssuedCertificate result = template.getCertificate(requestId);

        // Then
        assertNotNull(result);
        assertArrayEquals(material.leafCert.getEncoded(), result.leafCertificate());
        assertEquals(2, result.certificateChain().size());
        assertEquals(material.leafCert.getSerialNumber().toString(), result.serialNumber());
        assertNotNull(result.sha256Fingerprint());
        verify(pkiClient).getCertificate(requestId);
        // getStatus + getCertificate 成功路径各记一次查询指标
        verify(cryptoMetrics, times(2)).recordCertificateEnrollmentQuery(anyLong());
    }

    @Test
    void getCertificate_shouldThrowException_whenNotIssued() {
        // Given
        PkiClient.StatusResponse statusResponse = new PkiClient.StatusResponse(
                "request-202", "PENDING", "Processing"
        );
        when(pkiClient.getStatus("request-202")).thenReturn(statusResponse);

        // When & Then
        assertThrows(CertificateNotReadyException.class, () -> template.getCertificate("request-202"));
    }

    @Test
    void getCertificate_shouldThrowException_whenLeafPublicKeyMismatchesCsr() throws Exception {
        // Given
        PkiMaterial material = generatePkiMaterial();
        String requestId = applyCsr(material, "idem-501");

        // 由 Intermediate CA 签发一张公钥不同的叶子证书（同一 subject，冒充申请主体）
        KeyPair otherLeafKeyPair = generateKeyPair();
        X509Certificate mismatchedLeaf = issueLeaf(
                INTERMEDIATE_SUBJECT, material.intermediateKeyPair,
                LEAF_SUBJECT, otherLeafKeyPair.getPublic(), BigInteger.valueOf(99));

        when(pkiClient.getStatus(requestId)).thenReturn(
                new PkiClient.StatusResponse(requestId, "ISSUED", "Issued"));
        when(pkiClient.getCertificate(requestId)).thenReturn(
                certificateResponse(requestId, mismatchedLeaf.getEncoded(), material.chainPem));

        // When & Then
        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class, () -> template.getCertificate(requestId));
        assertTrue(ex.getMessage().contains("does not match the CSR public key"));
    }

    @Test
    void getCertificate_shouldThrowException_whenChainOrderIncorrect() throws Exception {
        // Given
        PkiMaterial material = generatePkiMaterial();
        String requestId = applyCsr(material, "idem-502");

        // 链首正确（Intermediate 签发 leaf）但链内出现无关 CA 破坏顺序：[Intermediate, Root, Unrelated]
        KeyPair unrelatedKeyPair = generateKeyPair();
        X509Certificate unrelatedCa = issueSelfSigned(
                new X500Name("CN=Unrelated CA"), unrelatedKeyPair, BigInteger.valueOf(8));
        String chainWithExtra = pem("CERTIFICATE", material.intermediateCert.getEncoded())
                + pem("CERTIFICATE", material.rootCert.getEncoded())
                + pem("CERTIFICATE", unrelatedCa.getEncoded());

        when(pkiClient.getStatus(requestId)).thenReturn(
                new PkiClient.StatusResponse(requestId, "ISSUED", "Issued"));
        when(pkiClient.getCertificate(requestId)).thenReturn(
                certificateResponse(requestId, material.leafCert.getEncoded(), chainWithExtra.getBytes()));

        // When & Then
        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class, () -> template.getCertificate(requestId));
        assertTrue(ex.getMessage().contains("order is incorrect"));
    }

    @Test
    void getCertificate_shouldThrowException_whenChainNotIssuingLeaf() throws Exception {
        // Given
        PkiMaterial material = generatePkiMaterial();
        String requestId = applyCsr(material, "idem-503");

        // 链首不是 leaf 的签发者（用无关 CA 冒充链首）
        KeyPair unrelatedKeyPair = generateKeyPair();
        X500Name unrelatedSubject = new X500Name("CN=Unrelated CA");
        X509Certificate unrelatedCa = issueSelfSigned(unrelatedSubject, unrelatedKeyPair, BigInteger.valueOf(7));
        byte[] unrelatedChain = pem("CERTIFICATE", unrelatedCa.getEncoded()).getBytes();

        when(pkiClient.getStatus(requestId)).thenReturn(
                new PkiClient.StatusResponse(requestId, "ISSUED", "Issued"));
        when(pkiClient.getCertificate(requestId)).thenReturn(
                certificateResponse(requestId, material.leafCert.getEncoded(), unrelatedChain));

        // When & Then
        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class, () -> template.getCertificate(requestId));
        assertTrue(ex.getMessage().contains("not at the head of the chain"));
    }

    @Test
    void getCertificate_shouldThrowException_whenChainEmpty() throws Exception {
        // Given
        PkiMaterial material = generatePkiMaterial();
        String requestId = applyCsr(material, "idem-504");

        when(pkiClient.getStatus(requestId)).thenReturn(
                new PkiClient.StatusResponse(requestId, "ISSUED", "Issued"));
        when(pkiClient.getCertificate(requestId)).thenReturn(
                certificateResponse(requestId, material.leafCert.getEncoded(), new byte[0]));

        // When & Then
        assertThrows(InvalidCertificateRequestException.class, () -> template.getCertificate(requestId));
    }

    @Test
    void getCertificate_shouldThrowException_whenCsrUnavailable() throws Exception {
        // Given
        PkiMaterial material = generatePkiMaterial();
        // 未 apply 直接 getCertificate（如进程重启后回放历史 requestId）——CSR 不可得，fail-closed
        when(pkiClient.getStatus("request-777")).thenReturn(
                new PkiClient.StatusResponse("request-777", "ISSUED", "Issued"));
        when(pkiClient.getCertificate("request-777")).thenReturn(
                certificateResponse("request-777", material.leafCert.getEncoded(), material.chainPem));

        // When & Then
        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class, () -> template.getCertificate("request-777"));
        assertTrue(ex.getMessage().contains("CSR for the request is unavailable"));
    }

    // ==================== 测试工具 ====================

    /** 提交真实 CSR 并返回 requestId */
    private String applyCsr(PkiMaterial material, String idempotencyKey) {
        SubjectRef subject = new SubjectRef(SubjectRef.SubjectType.CN, "test-service");
        CertApplyRequest request = new CertApplyRequest(
                allowedProfile, material.csrPem, subject, idempotencyKey, Map.of()
        );
        PkiClient.ApplyResponse pkiResponse = new PkiClient.ApplyResponse(
                "request-600", "ISSUED", "Issued"
        );
        when(pkiClient.submit(any())).thenReturn(pkiResponse);
        return template.apply(request).requestId();
    }

    private PkiClient.CertificateResponse certificateResponse(String requestId, byte[] leafDer, byte[] chainBytes) {
        return certificateResponse(requestId, leafDer, chainBytes, "1234567890");
    }

    private PkiClient.CertificateResponse certificateResponse(String requestId, byte[] leafDer, byte[] chainBytes,
                                                              String serialNumber) {
        return new PkiClient.CertificateResponse(
                requestId,
                leafDer,
                chainBytes,
                serialNumber,
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z"
        );
    }

    /** 生成 Root CA → Intermediate CA → Leaf（与 CSR 公钥一致）的完整 PKI 材料 */
    private PkiMaterial generatePkiMaterial() throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));

        KeyPair rootKeyPair = generateKeyPair();
        X509Certificate rootCert = issueSelfSigned(ROOT_SUBJECT, rootKeyPair, BigInteger.valueOf(1));

        KeyPair intermediateKeyPair = generateKeyPair();
        X509Certificate intermediateCert = issueCa(ROOT_SUBJECT, rootKeyPair,
                INTERMEDIATE_SUBJECT, intermediateKeyPair.getPublic(), BigInteger.valueOf(2));

        KeyPair leafKeyPair = generateKeyPair();
        X509Certificate leafCert = issueLeaf(INTERMEDIATE_SUBJECT, intermediateKeyPair,
                LEAF_SUBJECT, leafKeyPair.getPublic(), BigInteger.valueOf(3));

        // CSR（leaf 公钥）
        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(LEAF_SUBJECT, leafKeyPair.getPublic());
        PKCS10CertificationRequest csr = csrBuilder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(leafKeyPair.getPrivate()));
        byte[] csrPem = pem("CERTIFICATE REQUEST", csr.getEncoded()).getBytes();

        // 正确顺序链：[Intermediate, Root]
        byte[] chainPem = (pem("CERTIFICATE", intermediateCert.getEncoded())
                + pem("CERTIFICATE", rootCert.getEncoded())).getBytes();

        return new PkiMaterial(
                rootKeyPair, rootCert,
                intermediateKeyPair, intermediateCert,
                leafKeyPair, leafCert,
                csrPem, chainPem
        );
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private X509Certificate issueSelfSigned(X500Name subject, KeyPair keyPair, BigInteger serial) throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }

    private X509Certificate issueCa(X500Name issuer, KeyPair issuerKeyPair,
                                    X500Name subject, PublicKey publicKey, BigInteger serial) throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate())));
    }

    private X509Certificate issueLeaf(X500Name issuer, KeyPair issuerKeyPair,
                                      X500Name subject, PublicKey publicKey, BigInteger serial) throws Exception {
        Date notBefore = Date.from(Instant.now().minusSeconds(3600));
        Date notAfter = Date.from(Instant.now().plusSeconds(365L * 24 * 3600));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return toCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate())));
    }

    private X509Certificate toCertificate(X509CertificateHolder holder) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    /** 测试 PKI 材料 */
    private record PkiMaterial(
            KeyPair rootKeyPair,
            X509Certificate rootCert,
            KeyPair intermediateKeyPair,
            X509Certificate intermediateCert,
            KeyPair leafKeyPair,
            X509Certificate leafCert,
            byte[] csrPem,
            byte[] chainPem
    ) {}
}
