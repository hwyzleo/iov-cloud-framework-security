package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoException;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyScope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DefaultSigningTemplateTest {

    private KmsClient kmsClient;
    private CryptoMetrics cryptoMetrics;
    private DefaultSigningTemplate template;

    @BeforeEach
    void setUp() {
        kmsClient = mock(KmsClient.class);
        cryptoMetrics = mock(CryptoMetrics.class);
        template = new DefaultSigningTemplate(kmsClient, cryptoMetrics);
    }

    // ==================== sign ====================

    @Test
    void sign_orgScope_success() {
        byte[] data = "test data".getBytes();
        byte[] signature = new byte[]{1, 2, 3};
        when(kmsClient.signWith("idk-kts-signing", data, BizType.SignAlgo.ECDSA_P256))
                .thenReturn(signature);

        byte[] result = template.sign(BizType.IDK_KTS_SIGNING, KeyScope.org(), data);

        assertArrayEquals(signature, result);
        verify(kmsClient).signWith("idk-kts-signing", data, BizType.SignAlgo.ECDSA_P256);
        verify(cryptoMetrics).recordSigningSign(anyLong());
    }

    @Test
    void sign_nullBizType_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.sign(null, KeyScope.org(), new byte[]{1}));
    }

    @Test
    void sign_nullScope_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.sign(BizType.IDK_KTS_SIGNING, null, new byte[]{1}));
    }

    @Test
    void sign_nullData_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.sign(BizType.IDK_KTS_SIGNING, KeyScope.org(), null));
    }

    @Test
    void sign_symmetricBizType_failClosed() {
        CryptoException ex = assertThrows(CryptoException.class,
                () -> template.sign(BizType.TBOX_DEVICE_ROOT, KeyScope.device("SN123"), new byte[]{1}));
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE, ex.getReason());
        verify(kmsClient, never()).signWith(any(), any(), any());
    }

    @Test
    void sign_bizTypeDoesNotSupportSigning_failClosed() {
        for (BizType bt : BizType.values()) {
            if (bt.supportsSigning()) continue;
            assertThrows(CryptoException.class,
                    () -> template.sign(bt, KeyScope.org(), new byte[]{1}),
                    "Should fail-closed for " + bt.name());
        }
        verify(kmsClient, never()).signWith(any(), any(), any());
    }

    @Test
    void sign_anchorMismatch_failClosed() {
        CryptoException ex = assertThrows(CryptoException.class,
                () -> template.sign(BizType.IDK_KTS_SIGNING, KeyScope.vin("VIN123"), new byte[]{1}));
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE, ex.getReason());
        verify(kmsClient, never()).signWith(any(), any(), any());
    }

    @Test
    void sign_anchorMismatchDevice_failClosed() {
        CryptoException ex = assertThrows(CryptoException.class,
                () -> template.sign(BizType.IDK_KTS_SIGNING, KeyScope.device("SN123"), new byte[]{1}));
        assertEquals(CryptoException.Reason.INVALID_BIZ_TYPE, ex.getReason());
    }

    @Test
    void sign_kmsFailure_failClosed() {
        when(kmsClient.signWith(any(), any(), any()))
                .thenThrow(new CryptoException(CryptoException.Reason.DEPENDENCY_UNAVAILABLE, "KMS down") {});

        assertThrows(CryptoException.class,
                () -> template.sign(BizType.IDK_KTS_SIGNING, KeyScope.org(), new byte[]{1}));
        verify(cryptoMetrics).recordError();
    }

    // ==================== getPublicKey ====================

    @Test
    void getPublicKey_orgScope_success() {
        byte[] pubKey = new byte[]{10, 20, 30};
        when(kmsClient.getPublicKey("idk-kts-signing")).thenReturn(pubKey);

        byte[] result = template.getPublicKey(BizType.IDK_KTS_SIGNING, KeyScope.org());

        assertArrayEquals(pubKey, result);
        verify(kmsClient).getPublicKey("idk-kts-signing");
    }

    @Test
    void getPublicKey_anchorMismatch_failClosed() {
        assertThrows(CryptoException.class,
                () -> template.getPublicKey(BizType.IDK_KTS_SIGNING, KeyScope.device("SN123")));
        verify(kmsClient, never()).getPublicKey(any());
    }

    // ==================== verify ====================

    @Test
    void verify_orgScope_success() {
        byte[] data = "test data".getBytes();
        byte[] signature = new byte[]{1, 2, 3};
        when(kmsClient.verifyWith("idk-kts-signing", data, signature, BizType.SignAlgo.ECDSA_P256))
                .thenReturn(true);

        boolean result = template.verify(BizType.IDK_KTS_SIGNING, KeyScope.org(), data, signature);

        assertTrue(result);
        verify(cryptoMetrics).recordSigningVerify(anyLong());
    }

    @Test
    void verify_returnsFalse() {
        when(kmsClient.verifyWith(any(), any(), any(), any())).thenReturn(false);

        boolean result = template.verify(BizType.IDK_KTS_SIGNING, KeyScope.org(), new byte[]{1}, new byte[]{2});
        assertFalse(result);
    }

    @Test
    void verify_nullData_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.verify(BizType.IDK_KTS_SIGNING, KeyScope.org(), null, new byte[]{1}));
    }

    @Test
    void verify_nullSignature_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.verify(BizType.IDK_KTS_SIGNING, KeyScope.org(), new byte[]{1}, null));
    }

    // ==================== verifyWith ====================

    @Test
    void verifyWith_ecPublicKey_success() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        byte[] data = "test data".getBytes();
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        byte[] signature = sig.sign();

        byte[] pubKeySpki = kp.getPublic().getEncoded();

        boolean result = template.verifyWith(pubKeySpki, data, signature);
        assertTrue(result);
        verify(cryptoMetrics).recordSigningVerify(anyLong());
    }

    @Test
    void verifyWith_nullCertOrPublicKey_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.verifyWith(null, new byte[]{1}, new byte[]{2}));
    }

    @Test
    void verifyWith_nullData_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.verifyWith(new byte[]{1}, null, new byte[]{2}));
    }

    @Test
    void verifyWith_nullSignature_throwsNpe() {
        assertThrows(NullPointerException.class,
                () -> template.verifyWith(new byte[]{1}, new byte[]{2}, null));
    }

    @Test
    void verifyWith_invalidPublicKey_throwsCryptoException() {
        assertThrows(CryptoException.class,
                () -> template.verifyWith(new byte[]{0, 1, 2}, new byte[]{1}, new byte[]{2}));
        verify(cryptoMetrics).recordError();
    }

    @Test
    void verifyWith_rsaPublicKey_success() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] data = "test rsa data".getBytes();
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());
        sig.update(data);
        byte[] signature = sig.sign();

        byte[] pubKeySpki = kp.getPublic().getEncoded();

        boolean result = template.verifyWith(pubKeySpki, data, signature);
        assertTrue(result);
    }
}
