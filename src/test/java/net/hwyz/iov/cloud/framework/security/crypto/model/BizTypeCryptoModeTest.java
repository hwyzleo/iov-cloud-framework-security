package net.hwyz.iov.cloud.framework.security.crypto.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BizTypeCryptoModeTest {

    @Test
    void v2cCommRoot_isSession() {
        assertEquals(BizType.CryptoMode.SESSION, BizType.V2C_COMM_ROOT.cryptoMode());
    }

    @Test
    void deviceRoots_areEnvelope() {
        assertEquals(BizType.CryptoMode.ENVELOPE, BizType.TBOX_DEVICE_ROOT.cryptoMode());
        assertEquals(BizType.CryptoMode.ENVELOPE, BizType.CGW_DEVICE_ROOT.cryptoMode());
        assertEquals(BizType.CryptoMode.ENVELOPE, BizType.IMMO_GROUP_KEY.cryptoMode());
        assertEquals(BizType.CryptoMode.ENVELOPE, BizType.KLD_DEVICE_ROOT.cryptoMode());
    }

    @Test
    void cryptoMode_enumHasTwoValues() {
        assertEquals(2, BizType.CryptoMode.values().length);
        assertSame(BizType.CryptoMode.ENVELOPE, BizType.CryptoMode.valueOf("ENVELOPE"));
        assertSame(BizType.CryptoMode.SESSION, BizType.CryptoMode.valueOf("SESSION"));
    }
}
