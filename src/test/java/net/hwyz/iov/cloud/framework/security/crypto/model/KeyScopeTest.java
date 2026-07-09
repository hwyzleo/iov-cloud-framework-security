package net.hwyz.iov.cloud.framework.security.crypto.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyScopeTest {

    @Test
    void orgScope_anchorIsOrg() {
        KeyScope scope = KeyScope.org();
        assertEquals(BizType.Anchor.ORG, scope.anchor());
    }

    @Test
    void orgScope_subjectIsNull() {
        KeyScope scope = KeyScope.org();
        assertNull(scope.subject());
    }

    @Test
    void orgScope_isSingleton() {
        assertSame(KeyScope.org(), KeyScope.org());
    }

    @Test
    void vinScope_anchorIsVehicle() {
        KeyScope scope = KeyScope.vin("VIN12345678901234");
        assertEquals(BizType.Anchor.VEHICLE, scope.anchor());
    }

    @Test
    void vinScope_subjectIsNormalizedVin() {
        KeyScope scope = KeyScope.vin("  vin123  ");
        assertEquals("VIN123", scope.subject());
    }

    @Test
    void vinScope_nullVin_throwsNpe() {
        assertThrows(NullPointerException.class, () -> KeyScope.vin(null));
    }

    @Test
    void deviceScope_anchorIsDevice() {
        KeyScope scope = KeyScope.device("SN12345");
        assertEquals(BizType.Anchor.DEVICE, scope.anchor());
    }

    @Test
    void deviceScope_subjectIsTrimmed() {
        KeyScope scope = KeyScope.device("  SN12345  ");
        assertEquals("SN12345", scope.subject());
    }

    @Test
    void deviceScope_nullDeviceSn_throwsNpe() {
        assertThrows(NullPointerException.class, () -> KeyScope.device(null));
    }

    @Test
    void uidScope_anchorIsUser() {
        KeyScope scope = KeyScope.uid("UID123");
        assertEquals(BizType.Anchor.USER, scope.anchor());
    }

    @Test
    void uidScope_subjectIsTrimmed() {
        KeyScope scope = KeyScope.uid("  UID123  ");
        assertEquals("UID123", scope.subject());
    }

    @Test
    void uidScope_nullUid_throwsNpe() {
        assertThrows(NullPointerException.class, () -> KeyScope.uid(null));
    }

    @Test
    void orgScope_isOrgScopeInstance() {
        assertTrue(KeyScope.org() instanceof KeyScope.OrgScope);
    }

    @Test
    void vinScope_isVinScopeInstance() {
        assertTrue(KeyScope.vin("VIN123") instanceof KeyScope.VinScope);
    }

    @Test
    void deviceScope_isDeviceScopeInstance() {
        assertTrue(KeyScope.device("SN123") instanceof KeyScope.DeviceScope);
    }

    @Test
    void uidScope_isUidScopeInstance() {
        assertTrue(KeyScope.uid("UID123") instanceof KeyScope.UidScope);
    }
}
