package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.io.Serializable;
import java.util.Arrays;

/**
 * 密文线格式
 */
public class CipherPayload implements Serializable {

    private static final long serialVersionUID = 1L;

    private byte[] magic;
    private int ver;
    private int headerLen;
    private EnvelopeHeader header;
    private byte[] ciphertext;

    public CipherPayload() {
    }

    public byte[] getMagic() {
        return magic;
    }

    public void setMagic(byte[] magic) {
        this.magic = magic;
    }

    public int getVer() {
        return ver;
    }

    public void setVer(int ver) {
        this.ver = ver;
    }

    public int getHeaderLen() {
        return headerLen;
    }

    public void setHeaderLen(int headerLen) {
        this.headerLen = headerLen;
    }

    public EnvelopeHeader getHeader() {
        return header;
    }

    public void setHeader(EnvelopeHeader header) {
        this.header = header;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(byte[] ciphertext) {
        this.ciphertext = ciphertext;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CipherPayload that = (CipherPayload) o;
        return ver == that.ver && headerLen == that.headerLen
                && Arrays.equals(magic, that.magic)
                && java.util.Objects.equals(header, that.header)
                && Arrays.equals(ciphertext, that.ciphertext);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hash(ver, headerLen, header);
        result = 31 * result + Arrays.hashCode(magic);
        result = 31 * result + Arrays.hashCode(ciphertext);
        return result;
    }

    @Override
    public String toString() {
        return "CipherPayload{magic=" + Arrays.toString(magic) + ", ver=" + ver
                + ", headerLen=" + headerLen + ", header=" + header
                + ", ciphertext=" + Arrays.toString(ciphertext) + "}";
    }
}
