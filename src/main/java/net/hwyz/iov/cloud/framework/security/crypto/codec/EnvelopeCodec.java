package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.exception.IntegrityVerificationException;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * 信封编解码器
 * <p>
 * Wire format:
 * <ul>
 *   <li>ver=1 (legacy): {@code [magic(2B)][ver(1B)][headerLen(2B)][header][ciphertext]} -- 始终 ENVELOPE</li>
 *   <li>ver=2 (CR-005): {@code [magic(2B)][ver(1B)][mode(1B)][headerLen(2B)][header][ciphertext]}</li>
 * </ul>
 * 解码端按 ver 判断是否存在 mode 字节；老密文 (ver=1) 向后兼容，缺省 ENVELOPE。
 */
@Component
public class EnvelopeCodec {

    private static final byte[] MAGIC = {(byte) 0xCF, (byte) 0x01};
    private static final int VERSION_LEGACY = 1;
    private static final int VERSION_WITH_MODE = 2;
    private static final int MODE_ENVELOPE = 0;
    private static final int MODE_SESSION = 1;
    private static final int HEADER_LEN_SIZE = 2;

    /**
     * 编码信封头和密文（ENVELOPE 模式，ver=1 向后兼容）
     *
     * @param header     信封头
     * @param ciphertext 密文 + tag
     * @return 编码后的字节数组
     */
    public byte[] encode(EnvelopeHeader header, byte[] ciphertext) {
        return encode(header, ciphertext, MODE_ENVELOPE);
    }

    /**
     * 编码信封头和密文（指定模式）
     * <p>
     * ENVELOPE 模式使用 ver=1（向后兼容）；SESSION 模式使用 ver=2 + mode 字节。
     *
     * @param header     信封头
     * @param ciphertext 密文 + tag
     * @param mode       加解密模式（0=ENVELOPE, 1=SESSION）
     * @return 编码后的字节数组
     */
    public byte[] encode(EnvelopeHeader header, byte[] ciphertext, int mode) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // 写入魔数
            baos.write(MAGIC);

            // 写入版本号 + mode（ENVELOPE -> ver=1 legacy; SESSION -> ver=2 with mode）
            if (mode == MODE_SESSION) {
                baos.write(VERSION_WITH_MODE);
                baos.write(MODE_SESSION);
            } else {
                baos.write(VERSION_LEGACY);
            }

            // 编码信封头
            byte[] headerBytes = encodeHeader(header, mode);

            // 写入信封头长度
            ByteBuffer headerLenBuffer = ByteBuffer.allocate(HEADER_LEN_SIZE);
            headerLenBuffer.order(ByteOrder.BIG_ENDIAN);
            headerLenBuffer.putShort((short) headerBytes.length);
            baos.write(headerLenBuffer.array());

            // 写入信封头
            baos.write(headerBytes);

            // 写入密文 + tag
            baos.write(ciphertext);

            return baos.toByteArray();
        } catch (IOException e) {
            throw new IntegrityVerificationException("Failed to encode envelope", e);
        }
    }

    /**
     * 解码信封头和密文
     * <p>
     * 自动判别 ver=1（legacy, 无 mode, 始终 ENVELOPE）与 ver=2（带 mode 字节）。
     *
     * @param data 编码后的字节数组
     * @return 解码后的CipherPayload
     */
    public CipherPayload decode(byte[] data) {
        if (data == null || data.length < MAGIC.length + 1 + HEADER_LEN_SIZE) {
            throw new IntegrityVerificationException("Invalid cipher payload: too short");
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);

        // 验证魔数
        byte[] magic = new byte[MAGIC.length];
        buffer.get(magic);
        if (!java.util.Arrays.equals(magic, MAGIC)) {
            throw new IntegrityVerificationException("Invalid cipher payload: wrong magic");
        }

        // 读取版本号
        int ver = buffer.get() & 0xFF;

        // 读取 mode（ver=2 有 mode 字节；ver=1 无，缺省 ENVELOPE）
        int mode;
        if (ver == VERSION_WITH_MODE) {
            mode = buffer.get() & 0xFF;
        } else if (ver == VERSION_LEGACY) {
            mode = MODE_ENVELOPE;
        } else {
            throw new IntegrityVerificationException("Invalid cipher payload: unsupported version " + ver);
        }

        // 读取信封头长度
        int headerLen = buffer.getShort() & 0xFFFF;
        if (headerLen < 0 || headerLen > buffer.remaining()) {
            throw new IntegrityVerificationException("Invalid cipher payload: invalid header length");
        }

        // 读取信封头
        byte[] headerBytes = new byte[headerLen];
        buffer.get(headerBytes);
        EnvelopeHeader header = decodeHeader(headerBytes, mode);

        // 读取密文 + tag
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        CipherPayload payload = new CipherPayload();
        payload.setMagic(magic);
        payload.setVer(ver);
        payload.setMode(mode);
        payload.setHeaderLen(headerLen);
        payload.setHeader(header);
        payload.setCiphertext(ciphertext);

        return payload;
    }

    /**
     * 编码信封头
     * <p>
     * ENVELOPE: ver + keyId + keyVersion + alg + iv<br>
     * SESSION:  ver + keyName(存keyId字段) + alg + salt + iv(nonce)
     */
    private byte[] encodeHeader(EnvelopeHeader header, int mode) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // 写入版本号
            baos.write(header.getVer());

            if (mode == MODE_SESSION) {
                // 写入 keyName（复用 keyId 字段，供解密端定位会话根）
                byte[] keyNameBytes = header.getKeyId().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                ByteBuffer keyNameLenBuffer = ByteBuffer.allocate(2);
                keyNameLenBuffer.order(ByteOrder.BIG_ENDIAN);
                keyNameLenBuffer.putShort((short) keyNameBytes.length);
                baos.write(keyNameLenBuffer.array());
                baos.write(keyNameBytes);

                // 写入算法长度和内容
                byte[] algBytes = header.getAlg().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                ByteBuffer algLenBuffer = ByteBuffer.allocate(2);
                algLenBuffer.order(ByteOrder.BIG_ENDIAN);
                algLenBuffer.putShort((short) algBytes.length);
                baos.write(algLenBuffer.array());
                baos.write(algBytes);

                // 写入 salt 长度和内容
                ByteBuffer saltLenBuffer = ByteBuffer.allocate(2);
                saltLenBuffer.order(ByteOrder.BIG_ENDIAN);
                saltLenBuffer.putShort((short) header.getSalt().length);
                baos.write(saltLenBuffer.array());
                baos.write(header.getSalt());

                // 写入 IV(nonce) 长度和内容
                ByteBuffer ivLenBuffer = ByteBuffer.allocate(2);
                ivLenBuffer.order(ByteOrder.BIG_ENDIAN);
                ivLenBuffer.putShort((short) header.getIv().length);
                baos.write(ivLenBuffer.array());
                baos.write(header.getIv());
            } else {
                // ENVELOPE: keyId + keyVersion + alg + iv
                // 写入keyId长度和内容
                byte[] keyIdBytes = header.getKeyId().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                ByteBuffer keyIdLenBuffer = ByteBuffer.allocate(2);
                keyIdLenBuffer.order(ByteOrder.BIG_ENDIAN);
                keyIdLenBuffer.putShort((short) keyIdBytes.length);
                baos.write(keyIdLenBuffer.array());
                baos.write(keyIdBytes);

                // 写入keyVersion
                ByteBuffer keyVersionBuffer = ByteBuffer.allocate(4);
                keyVersionBuffer.order(ByteOrder.BIG_ENDIAN);
                keyVersionBuffer.putInt(header.getKeyVersion());
                baos.write(keyVersionBuffer.array());

                // 写入算法长度和内容
                byte[] algBytes = header.getAlg().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                ByteBuffer algLenBuffer = ByteBuffer.allocate(2);
                algLenBuffer.order(ByteOrder.BIG_ENDIAN);
                algLenBuffer.putShort((short) algBytes.length);
                baos.write(algLenBuffer.array());
                baos.write(algBytes);

                // 写入IV长度和内容
                ByteBuffer ivLenBuffer = ByteBuffer.allocate(2);
                ivLenBuffer.order(ByteOrder.BIG_ENDIAN);
                ivLenBuffer.putShort((short) header.getIv().length);
                baos.write(ivLenBuffer.array());
                baos.write(header.getIv());
            }

            return baos.toByteArray();
        } catch (IOException e) {
            throw new IntegrityVerificationException("Failed to encode header", e);
        }
    }

    /**
     * 解码信封头
     */
    private EnvelopeHeader decodeHeader(byte[] data, int mode) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.BIG_ENDIAN);

            EnvelopeHeader header = new EnvelopeHeader();

            // 读取版本号
            header.setVer(buffer.get() & 0xFF);
            header.setMode(mode);

            if (mode == MODE_SESSION) {
                // SESSION: keyName + alg + salt + iv(nonce)

                // 读取 keyName（存入 keyId 字段）
                int keyNameLen = buffer.getShort() & 0xFFFF;
                byte[] keyNameBytes = new byte[keyNameLen];
                buffer.get(keyNameBytes);
                header.setKeyId(new String(keyNameBytes, java.nio.charset.StandardCharsets.UTF_8));

                // 读取算法
                int algLen = buffer.getShort() & 0xFFFF;
                byte[] algBytes = new byte[algLen];
                buffer.get(algBytes);
                header.setAlg(new String(algBytes, java.nio.charset.StandardCharsets.UTF_8));

                // 读取 salt
                int saltLen = buffer.getShort() & 0xFFFF;
                byte[] salt = new byte[saltLen];
                buffer.get(salt);
                header.setSalt(salt);

                // 读取 IV(nonce)
                int ivLen = buffer.getShort() & 0xFFFF;
                byte[] iv = new byte[ivLen];
                buffer.get(iv);
                header.setIv(iv);
            } else {
                // ENVELOPE: keyId + keyVersion + alg + iv

                // 读取keyId
                int keyIdLen = buffer.getShort() & 0xFFFF;
                byte[] keyIdBytes = new byte[keyIdLen];
                buffer.get(keyIdBytes);
                header.setKeyId(new String(keyIdBytes, java.nio.charset.StandardCharsets.UTF_8));

                // 读取keyVersion
                header.setKeyVersion(buffer.getInt());

                // 读取算法
                int algLen = buffer.getShort() & 0xFFFF;
                byte[] algBytes = new byte[algLen];
                buffer.get(algBytes);
                header.setAlg(new String(algBytes, java.nio.charset.StandardCharsets.UTF_8));

                // 读取IV
                int ivLen = buffer.getShort() & 0xFFFF;
                byte[] iv = new byte[ivLen];
                buffer.get(iv);
                header.setIv(iv);
            }

            return header;
        } catch (Exception e) {
            throw new IntegrityVerificationException("Failed to decode header", e);
        }
    }
}
