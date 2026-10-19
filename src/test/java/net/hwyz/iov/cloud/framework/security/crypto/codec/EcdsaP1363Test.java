package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.exception.ImportProofRejectedException;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofAlgorithm;
import net.hwyz.iov.cloud.framework.security.crypto.model.importproof.ImportProofRejectReason;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * P1363 / low-S 编解码与验签单元测试（FW-SEC-DSN-CR-016 §5）。
 */
class EcdsaP1363Test {

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = generator.generateKeyPair();
    }

    private byte[] signLowS(byte[] message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(message);
        return EcdsaP1363.derToP1363(signature.sign());
    }

    @Test
    void verify_validP1363LowS_returnsTrue() throws Exception {
        byte[] message = "canonical-proof-input".getBytes(StandardCharsets.UTF_8);
        byte[] proof = signLowS(message);

        assertEquals(ImportProofAlgorithm.SIGNATURE_LENGTH, proof.length);
        assertTrue(EcdsaP1363.verify(keyPair.getPublic(), message, proof));
    }

    @Test
    void verify_tamperedMessage_returnsFalse() throws Exception {
        byte[] proof = signLowS("message-a".getBytes(StandardCharsets.UTF_8));
        assertFalse(EcdsaP1363.verify(keyPair.getPublic(),
                "message-b".getBytes(StandardCharsets.UTF_8), proof));
    }

    @Test
    void parse_rejectsWrongLength() {
        assertEquals(ImportProofRejectReason.INVALID_LENGTH, rejectReasonEcdsa(new byte[63]));
        assertEquals(ImportProofRejectReason.INVALID_LENGTH, rejectReasonEcdsa(new byte[65]));
        assertEquals(ImportProofRejectReason.INVALID_LENGTH, rejectReasonEcdsa(null));
    }

    @Test
    void parse_rejectsZeroScalars() {
        assertEquals(ImportProofRejectReason.INVALID_SCALAR,
                rejectReasonEcdsa(proof(BigInteger.ZERO, BigInteger.ONE)));
        assertEquals(ImportProofRejectReason.INVALID_SCALAR,
                rejectReasonEcdsa(proof(BigInteger.ONE, BigInteger.ZERO)));
    }

    @Test
    void parse_rejectsScalarsOutOfRange() {
        assertEquals(ImportProofRejectReason.INVALID_SCALAR,
                rejectReasonEcdsa(proof(EcdsaP1363.P256_ORDER_N, BigInteger.ONE)));
        assertEquals(ImportProofRejectReason.INVALID_SCALAR,
                rejectReasonEcdsa(proof(BigInteger.ONE, EcdsaP1363.P256_ORDER_N)));
        assertEquals(ImportProofRejectReason.INVALID_SCALAR,
                rejectReasonEcdsa(proof(EcdsaP1363.P256_ORDER_N.add(BigInteger.ONE), BigInteger.ONE)));
    }

    @Test
    void parse_rejectsHighS() {
        BigInteger highS = EcdsaP1363.P256_ORDER_N.subtract(BigInteger.ONE);
        assertEquals(ImportProofRejectReason.HIGH_S, rejectReasonEcdsa(proof(BigInteger.ONE, highS)));
    }

    @Test
    void parse_acceptsBoundaryLowS() {
        EcdsaP1363.Scalars scalars =
                EcdsaP1363.parse(proof(BigInteger.ONE, EcdsaP1363.P256_HALF_N));
        assertEquals(EcdsaP1363.P256_HALF_N, scalars.s());
    }

    @Test
    void derToP1363_normalizesHighSToLowS() throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        byte[] message = "normalize".getBytes(StandardCharsets.UTF_8);
        signature.update(message);
        byte[] der = signature.sign();

        // 直接解析 DER 得到未归一化 s，人工构造 high-S P1363 再经 wire 解析应被拒绝。
        byte[] p1363 = EcdsaP1363.derToP1363(der);
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(p1363, 32, 64));
        assertTrue(s.compareTo(EcdsaP1363.P256_HALF_N) <= 0, "derToP1363 输出必须为 low-S");

        byte[] highS = p1363.clone();
        byte[] flipped = EcdsaP1363.P256_ORDER_N.subtract(s).toByteArray();
        byte[] padded = leftPad32(flipped);
        System.arraycopy(padded, 0, highS, 32, 32);
        assertEquals(ImportProofRejectReason.HIGH_S, rejectReasonEcdsa(highS));
    }

    @Test
    void encodeDer_roundTripsThroughP1363() {
        BigInteger r = BigInteger.valueOf(0x7F);
        BigInteger s = BigInteger.valueOf(0x80);
        byte[] der = EcdsaP1363.encodeDer(new EcdsaP1363.Scalars(r, s));
        assertEquals(0x30, der[0] & 0xFF);
        byte[] p1363 = EcdsaP1363.derToP1363(der);
        assertEquals(r, new BigInteger(1, Arrays.copyOfRange(p1363, 0, 32)));
        assertEquals(s, new BigInteger(1, Arrays.copyOfRange(p1363, 32, 64)));
    }

    @Test
    void providerAvailable_true() {
        assertTrue(EcdsaP1363.providerAvailable());
    }

    private static ImportProofRejectReason rejectReasonEcdsa(byte[] proof) {
        ImportProofRejectedException ex =
                assertThrows(ImportProofRejectedException.class, () -> EcdsaP1363.parse(proof));
        return ex.rejectReason();
    }

    private static byte[] proof(BigInteger r, BigInteger s) {
        byte[] out = new byte[64];
        System.arraycopy(leftPad32(r.toByteArray()), 0, out, 0, 32);
        System.arraycopy(leftPad32(s.toByteArray()), 0, out, 32, 32);
        return out;
    }

    private static byte[] leftPad32(byte[] value) {
        byte[] out = new byte[32];
        if (value.length >= 32) {
            System.arraycopy(value, value.length - 32, out, 0, 32);
        } else {
            System.arraycopy(value, 0, out, 32 - value.length, value.length);
        }
        return out;
    }
}
