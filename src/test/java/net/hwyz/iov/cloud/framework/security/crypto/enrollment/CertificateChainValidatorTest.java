package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CertificateChainValidator 单元测试（FW-SEC-DSN-CR-008 §3.2/§9）
 */
class CertificateChainValidatorTest {

    private CertificateChainValidator validator;
    private TestPkiMaterial.Pki material;
    private String rootFingerprint;
    private StepCaProfilePolicy policy;

    @BeforeEach
    void setUp() throws Exception {
        validator = new CertificateChainValidator();
        material = TestPkiMaterial.generate(true, "TBOX-00000000000000000000000000000001");
        rootFingerprint = EnrollmentRecord.fingerprintHex(material.rootCert().getEncoded());
        policy = new StepCaProfilePolicy(
                "TBOX_IDENTITY", "openiov", "kid-1", Duration.ofDays(365),
                List.of("EC_P256"), List.of("CLIENT_AUTH"), "TBOX");
    }

    // ==================== 结构一致性（legacy + step-ca 共用） ====================

    @Test
    void validateCertificateConsistency_shouldPass_withValidMaterial() throws Exception {
        List<byte[]> chain = validator.parseCertificateChain(material.chainPem());
        validator.validateCertificateConsistency(
                material.leafCert().getEncoded(), chain, material.csrPem());
    }

    @Test
    void validateCertificateConsistency_shouldFail_whenCsrMissing() throws Exception {
        List<byte[]> chain = validator.parseCertificateChain(material.chainPem());
        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class,
                () -> validator.validateCertificateConsistency(
                        material.leafCert().getEncoded(), chain, null));
        assertTrue(ex.getMessage().contains("CSR for the request is unavailable"));
    }

    @Test
    void validateCertificateConsistency_shouldFail_whenLeafPublicKeyMismatchesCsr() throws Exception {
        java.security.KeyPair otherKeyPair = TestPkiMaterial.generateKeyPair();
        java.security.cert.X509Certificate mismatched = TestPkiMaterial.issueLeaf(
                TestPkiMaterial.INTERMEDIATE_SUBJECT, material.intermediateKeyPair(),
                TestPkiMaterial.LEAF_SUBJECT, otherKeyPair.getPublic(),
                java.math.BigInteger.valueOf(99), true, null);
        List<byte[]> chain = validator.parseCertificateChain(material.chainPem());

        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class,
                () -> validator.validateCertificateConsistency(
                        mismatched.getEncoded(), chain, material.csrPem()));
        assertTrue(ex.getMessage().contains("does not match the CSR public key"));
    }

    @Test
    void validateCertificateConsistency_shouldFail_whenChainOrderIncorrect() throws Exception {
        java.security.KeyPair unrelatedKeyPair = TestPkiMaterial.generateKeyPair();
        java.security.cert.X509Certificate unrelated = TestPkiMaterial.issueSelfSigned(
                new org.bouncycastle.asn1.x500.X500Name("CN=Unrelated CA"),
                unrelatedKeyPair, java.math.BigInteger.valueOf(8));
        String badChain = TestPkiMaterial.pem("CERTIFICATE", material.intermediateCert().getEncoded())
                + TestPkiMaterial.pem("CERTIFICATE", material.rootCert().getEncoded())
                + TestPkiMaterial.pem("CERTIFICATE", unrelated.getEncoded());
        List<byte[]> chain = validator.parseCertificateChain(badChain.getBytes());

        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class,
                () -> validator.validateCertificateConsistency(
                        material.leafCert().getEncoded(), chain, material.csrPem()));
        assertTrue(ex.getMessage().contains("order is incorrect"));
    }

    // ==================== step-ca 完整校验 ====================

    @Test
    void validateIssued_shouldPass_withValidMaterial() throws Exception {
        List<byte[]> chain = List.of(
                material.intermediateCert().getEncoded(),
                material.rootCert().getEncoded());
        validator.validateIssued(material.leafCert().getEncoded(), chain, material.csrPem(), policy, rootFingerprint);
    }

    @Test
    void validateIssued_shouldFail_whenRootFingerprintMismatch() throws Exception {
        List<byte[]> chain = List.of(
                material.intermediateCert().getEncoded(),
                material.rootCert().getEncoded());
        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class,
                () -> validator.validateIssued(material.leafCert().getEncoded(), chain,
                        material.csrPem(), policy, "0000000000000000000000000000000000000000000000000000000000000000"));
        assertTrue(ex.getMessage().contains("root"));
    }

    @Test
    void validateIssued_shouldFail_whenSignatureInvalid() throws Exception {
        // 用无关 key 签发叶子（签名校验失败）
        java.security.KeyPair unrelatedKeyPair = TestPkiMaterial.generateKeyPair();
        java.security.cert.X509Certificate forged = TestPkiMaterial.issueLeaf(
                TestPkiMaterial.INTERMEDIATE_SUBJECT, unrelatedKeyPair,
                TestPkiMaterial.LEAF_SUBJECT, material.leafKeyPair().getPublic(),
                java.math.BigInteger.valueOf(42), true, "TBOX-00000000000000000000000000000001");
        List<byte[]> chain = List.of(
                material.intermediateCert().getEncoded(),
                material.rootCert().getEncoded());

        assertThrows(InvalidCertificateRequestException.class,
                () -> validator.validateIssued(forged.getEncoded(), chain,
                        material.csrPem(), policy, rootFingerprint));
    }

    @Test
    void validateIssued_shouldFail_whenRequiredEkuMissing() throws Exception {
        // 无 clientAuth EKU 的叶子
        TestPkiMaterial.Pki noEku = TestPkiMaterial.generate(false, "TBOX-00000000000000000000000000000001");
        List<byte[]> chain = List.of(
                noEku.intermediateCert().getEncoded(),
                noEku.rootCert().getEncoded());

        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class,
                () -> validator.validateIssued(noEku.leafCert().getEncoded(), chain,
                        noEku.csrPem(), policy,
                        EnrollmentRecord.fingerprintHex(noEku.rootCert().getEncoded())));
        assertTrue(ex.getMessage().contains("EKU"));
    }

    @Test
    void validateIssued_shouldFail_whenValidityExceedsMax() throws Exception {
        // maxValidity 极小（1 分钟），必定超限
        StepCaProfilePolicy tinyPolicy = new StepCaProfilePolicy(
                "TBOX_IDENTITY", "openiov", "kid-1", Duration.ofMinutes(1),
                List.of("EC_P256"), List.of("CLIENT_AUTH"), "TBOX");
        List<byte[]> chain = List.of(
                material.intermediateCert().getEncoded(),
                material.rootCert().getEncoded());

        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class,
                () -> validator.validateIssued(material.leafCert().getEncoded(), chain,
                        material.csrPem(), tinyPolicy, rootFingerprint));
        assertTrue(ex.getMessage().contains("max-validity"));
    }

    @Test
    void validateIssued_shouldFail_whenSubjectRuleViolated() throws Exception {
        StepCaProfilePolicy otherRule = new StepCaProfilePolicy(
                "TBOX_IDENTITY", "openiov", "kid-1", Duration.ofDays(365),
                List.of("EC_P256"), List.of("CLIENT_AUTH"), "VIN");
        List<byte[]> chain = List.of(
                material.intermediateCert().getEncoded(),
                material.rootCert().getEncoded());

        InvalidCertificateRequestException ex = assertThrows(
                InvalidCertificateRequestException.class,
                () -> validator.validateIssued(material.leafCert().getEncoded(), chain,
                        material.csrPem(), otherRule, rootFingerprint));
        assertTrue(ex.getMessage().contains("subject rule"));
    }

    @Test
    void validateIssued_shouldFail_whenKeyAlgorithmNotAllowed() throws Exception {
        StepCaProfilePolicy rsaOnly = new StepCaProfilePolicy(
                "TBOX_IDENTITY", "openiov", "kid-1", Duration.ofDays(365),
                List.of("RSA_2048"), List.of("CLIENT_AUTH"), "TBOX");
        List<byte[]> chain = List.of(
                material.intermediateCert().getEncoded(),
                material.rootCert().getEncoded());

        assertThrows(InvalidCertificateRequestException.class,
                () -> validator.validateIssued(material.leafCert().getEncoded(), chain,
                        material.csrPem(), rsaOnly, rootFingerprint));
    }

    @Test
    void validateIssued_shouldFail_whenLeafIsCa() throws Exception {
        // 用 CA 证书冒充叶子（basicConstraints 违规）
        List<byte[]> chain = List.of(
                material.rootCert().getEncoded());
        assertThrows(InvalidCertificateRequestException.class,
                () -> validator.validateIssued(material.rootCert().getEncoded(), chain,
                        material.csrPem(), policy, rootFingerprint));
    }
}
