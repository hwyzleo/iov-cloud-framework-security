package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.io.Serializable;
import java.util.Arrays;

/**
 * 信封头
 */
public class EnvelopeHeader implements Serializable {

    private static final long serialVersionUID = 1L;

    private int ver;
    private String keyId;
    private int keyVersion;
    private String alg;
    private byte[] iv;

    public EnvelopeHeader() {
    }

    public int getVer() {
        return ver;
    }

    public void setVer(int ver) {
        this.ver = ver;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public int getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(int keyVersion) {
        this.keyVersion = keyVersion;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EnvelopeHeader that = (EnvelopeHeader) o;
        return ver == that.ver && keyVersion == that.keyVersion
                && java.util.Objects.equals(keyId, that.keyId)
                && java.util.Objects.equals(alg, that.alg)
                && Arrays.equals(iv, that.iv);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hash(ver, keyId, keyVersion, alg);
        result = 31 * result + Arrays.hashCode(iv);
        return result;
    }

    @Override
    public String toString() {
        return "EnvelopeHeader{ver=" + ver + ", keyId='" + keyId + "', keyVersion=" + keyVersion
                + ", alg='" + alg + "', iv=" + Arrays.toString(iv) + "}";
    }
}
