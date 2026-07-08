package net.hwyz.iov.cloud.framework.security.crypto.kdf;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

class SessionKdfTest {

    @Test
    void deriveSessionKey_deterministic() {
        byte[] root = "test-root-32-bytes-1234567890ab".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "test-salt-16bytes".getBytes(StandardCharsets.UTF_8);
        byte[] info = SessionKdf.buildInfo("V2C_COMM_ROOT");

        byte[] key1 = SessionKdf.deriveSessionKey(root, salt, info);
        byte[] key2 = SessionKdf.deriveSessionKey(root, salt, info);

        assertEquals(32, key1.length);
        assertArrayEquals(key1, key2);
    }

    @Test
    void deriveSessionKey_differentSalt_differentKey() {
        byte[] root = "test-root-32-bytes-1234567890ab".getBytes(StandardCharsets.UTF_8);
        byte[] info = SessionKdf.buildInfo("V2C_COMM_ROOT");

        byte[] salt1 = "salt-one-16bytes".getBytes(StandardCharsets.UTF_8);
        byte[] salt2 = "salt-two-16bytes".getBytes(StandardCharsets.UTF_8);

        byte[] key1 = SessionKdf.deriveSessionKey(root, salt1, info);
        byte[] key2 = SessionKdf.deriveSessionKey(root, salt2, info);

        assertFalse(java.util.Arrays.equals(key1, key2));
    }

    @Test
    void deriveSessionKey_differentRoot_differentKey() {
        byte[] salt = "test-salt-16bytes".getBytes(StandardCharsets.UTF_8);
        byte[] info = SessionKdf.buildInfo("V2C_COMM_ROOT");

        byte[] key1 = SessionKdf.deriveSessionKey(
                "root-one-32-bytes-1234567890abc".getBytes(StandardCharsets.UTF_8), salt, info);
        byte[] key2 = SessionKdf.deriveSessionKey(
                "root-two-32-bytes-1234567890abc".getBytes(StandardCharsets.UTF_8), salt, info);

        assertFalse(java.util.Arrays.equals(key1, key2));
    }

    @Test
    void generateSalt_randomAnd16Bytes() {
        byte[] salt1 = SessionKdf.generateSalt();
        byte[] salt2 = SessionKdf.generateSalt();

        assertEquals(16, salt1.length);
        assertEquals(16, salt2.length);
        assertFalse(java.util.Arrays.equals(salt1, salt2));
    }

    @Test
    void buildInfo_correctPrefix() {
        byte[] info = SessionKdf.buildInfo("V2C_COMM_ROOT");
        String infoStr = new String(info, StandardCharsets.UTF_8);
        assertEquals("iov-session:V2C_COMM_ROOT", infoStr);
    }

    @Test
    void computeKcv_returns4Bytes() throws Exception {
        byte[] data = "test-data".getBytes(StandardCharsets.UTF_8);
        byte[] kcv = SessionKdf.computeKcv(data);

        assertEquals(4, kcv.length);

        byte[] expectedHash = MessageDigest.getInstance("SHA-256").digest(data);
        assertArrayEquals(java.util.Arrays.copyOf(expectedHash, 4), kcv);
    }

    @Test
    void hkdf_matchesRfc5869_manual() throws Exception {
        byte[] ikm = new byte[22];
        byte[] salt = new byte[13];
        byte[] info = new byte[10];

        byte[] prk = SessionKdf.extract(salt, ikm);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] expectedPrk = mac.doFinal(ikm);

        assertArrayEquals(expectedPrk, prk);
    }
}
