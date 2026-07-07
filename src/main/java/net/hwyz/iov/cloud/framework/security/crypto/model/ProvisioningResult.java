package net.hwyz.iov.cloud.framework.security.crypto.model;

import java.io.Serializable;
import java.util.Arrays;

/**
 * 派生/封装结果（内部对象，不落库）
 * <p>
 * 派生（{@code deriveByVin} / {@code deriveByUid}）返回纯派生结果（{@code wrappedMaterial} 为 {@code null}）；
 * 封装（{@code wrapByVin} / {@code wrapByUid}）返回含经 {@code dev-{sn|uid}} 封装的密文物料。
 */
public final class ProvisioningResult implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 命名密钥引用 / 版本 */
    private String kmsKeyRef;
    /** 密钥规格 / 长度 */
    private String keySpec;
    /** KMS 提供方 */
    private String provider;
    /** 派生 / 封装算法，如 HMAC-SHA256 */
    private String algorithm;
    /** 密钥校验值 (Key Check Value) */
    private byte[] kcv;
    /** 器件级封装密文物料（仅 wrapByVin/wrapByUid 非 null；派生为 null） */
    private byte[] wrappedMaterial;

    public ProvisioningResult() {
    }

    public String getKmsKeyRef() {
        return kmsKeyRef;
    }

    public void setKmsKeyRef(String kmsKeyRef) {
        this.kmsKeyRef = kmsKeyRef;
    }

    public String getKeySpec() {
        return keySpec;
    }

    public void setKeySpec(String keySpec) {
        this.keySpec = keySpec;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public byte[] getKcv() {
        return kcv;
    }

    public void setKcv(byte[] kcv) {
        this.kcv = kcv;
    }

    public byte[] getWrappedMaterial() {
        return wrappedMaterial;
    }

    public void setWrappedMaterial(byte[] wrappedMaterial) {
        this.wrappedMaterial = wrappedMaterial;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProvisioningResult that = (ProvisioningResult) o;
        return java.util.Objects.equals(kmsKeyRef, that.kmsKeyRef)
                && java.util.Objects.equals(keySpec, that.keySpec)
                && java.util.Objects.equals(provider, that.provider)
                && java.util.Objects.equals(algorithm, that.algorithm)
                && Arrays.equals(kcv, that.kcv)
                && Arrays.equals(wrappedMaterial, that.wrappedMaterial);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hash(kmsKeyRef, keySpec, provider, algorithm);
        result = 31 * result + Arrays.hashCode(kcv);
        result = 31 * result + Arrays.hashCode(wrappedMaterial);
        return result;
    }

    @Override
    public String toString() {
        return "ProvisioningResult{kmsKeyRef='" + kmsKeyRef + "', keySpec='" + keySpec
                + "', provider='" + provider + "', algorithm='" + algorithm
                + "', kcv=" + Arrays.toString(kcv)
                + ", wrappedMaterial=" + (wrappedMaterial == null ? "null" : "[" + wrappedMaterial.length + " bytes]") + "}";
    }
}
