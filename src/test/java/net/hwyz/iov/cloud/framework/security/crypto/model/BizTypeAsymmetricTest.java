package net.hwyz.iov.cloud.framework.security.crypto.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BizTypeAsymmetricTest {

    @Test
    void idkKtsSigning_isAsymmetric() {
        assertEquals(BizType.KeyType.ASYMMETRIC, BizType.IDK_KTS_SIGNING.keyType());
    }

    @Test
    void idkKtsSigning_supportsSigning() {
        assertTrue(BizType.IDK_KTS_SIGNING.supportsSigning());
    }

    @Test
    void idkKtsSigning_signAlgoIsEcdsaP256() {
        assertEquals(BizType.SignAlgo.ECDSA_P256, BizType.IDK_KTS_SIGNING.signAlgo());
    }

    @Test
    void idkKtsSigning_anchorIsOrg() {
        assertEquals(BizType.Anchor.ORG, BizType.IDK_KTS_SIGNING.prov().anchor());
    }

    @Test
    void idkKtsSigning_deviceCategoryIsNull() {
        assertNull(BizType.IDK_KTS_SIGNING.getDeviceCategory());
    }

    @Test
    void idkKtsSigning_cryptoModeIsNull() {
        assertNull(BizType.IDK_KTS_SIGNING.cryptoMode());
    }

    @Test
    void idkKtsSigning_doesNotSupportData() {
        assertFalse(BizType.IDK_KTS_SIGNING.supportsData());
    }

    @Test
    void idkKtsSigning_supportsProvision() {
        assertTrue(BizType.IDK_KTS_SIGNING.supportsProvision());
    }

    @Test
    void idkKtsSigning_keyName() {
        assertEquals("idk-kts-signing", BizType.IDK_KTS_SIGNING.prov().keyName());
    }

    @Test
    void existingSymmetricEntries_areSymmetric() {
        for (BizType bt : BizType.values()) {
            if (bt == BizType.IDK_KTS_SIGNING) continue;
            assertEquals(BizType.KeyType.SYMMETRIC, bt.keyType(),
                    bt.name() + " should be SYMMETRIC");
            assertFalse(bt.supportsSigning(),
                    bt.name() + " should not support signing");
            assertNull(bt.signAlgo(),
                    bt.name() + " should have null signAlgo");
        }
    }

    @Test
    void anchorEnumHasFourValues() {
        assertEquals(4, BizType.Anchor.values().length);
        assertSame(BizType.Anchor.VEHICLE, BizType.Anchor.valueOf("VEHICLE"));
        assertSame(BizType.Anchor.DEVICE, BizType.Anchor.valueOf("DEVICE"));
        assertSame(BizType.Anchor.ORG, BizType.Anchor.valueOf("ORG"));
        assertSame(BizType.Anchor.USER, BizType.Anchor.valueOf("USER"));
    }

    @Test
    void keyTypeEnumHasTwoValues() {
        assertEquals(2, BizType.KeyType.values().length);
        assertSame(BizType.KeyType.SYMMETRIC, BizType.KeyType.valueOf("SYMMETRIC"));
        assertSame(BizType.KeyType.ASYMMETRIC, BizType.KeyType.valueOf("ASYMMETRIC"));
    }

    @Test
    void signAlgoEnumHasTwoValues() {
        assertEquals(2, BizType.SignAlgo.values().length);
        assertSame(BizType.SignAlgo.ECDSA_P256, BizType.SignAlgo.valueOf("ECDSA_P256"));
        assertSame(BizType.SignAlgo.EDDSA_ED25519, BizType.SignAlgo.valueOf("EDDSA_ED25519"));
    }
}
