package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 证书/CSR PEM 编解码工具（step-ca 适配用）
 */
public final class CertPem {

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----\\s*(.+?)\\s*-----END \\1-----", Pattern.DOTALL);

    private CertPem() {
    }

    /**
     * 将 DER 证书编码为 PEM。
     */
    public static String toPemCertificate(byte[] der) {
        return toPem("CERTIFICATE", der);
    }

    /**
     * 将 DER CSR 编码为 PEM（PKCS#10）。
     */
    public static String toPemCsr(byte[] der) {
        return toPem("CERTIFICATE REQUEST", der);
    }

    /**
     * 将 PEM（任意证书类型）解码为 DER。
     */
    public static byte[] derFromPem(String pem) {
        Matcher matcher = PEM_BLOCK.matcher(pem.trim());
        if (!matcher.find()) {
            throw new InvalidCertificateRequestException("Not a valid PEM block");
        }
        try {
            return Base64.getMimeDecoder().decode(matcher.group(2).replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            throw new InvalidCertificateRequestException("PEM base64 is malformed", e);
        }
    }

    /**
     * 解析 PEM 中的单个证书。
     */
    public static X509Certificate parseCertificate(String pem) {
        return parseCertificate(derFromPem(pem));
    }

    /**
     * 解析 DER 证书。
     */
    public static X509Certificate parseCertificate(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new InvalidCertificateRequestException("Failed to parse certificate", e);
        }
    }

    /**
     * 解析 PEM bundle（可含多张证书）为 DER 列表。
     */
    public static List<byte[]> parsePemBundle(String pem) {
        List<byte[]> result = new ArrayList<>();
        Matcher matcher = PEM_BLOCK.matcher(pem);
        while (matcher.find()) {
            result.add(Base64.getMimeDecoder().decode(matcher.group(2).replaceAll("\\s", "")));
        }
        if (result.isEmpty()) {
            throw new InvalidCertificateRequestException("PEM bundle contains no certificates");
        }
        return result;
    }

    /**
     * 将多张 DER 证书拼接为 PEM bundle。
     */
    public static String joinPem(List<byte[]> chainDer) {
        StringBuilder sb = new StringBuilder();
        for (byte[] der : chainDer) {
            sb.append(toPem("CERTIFICATE", der));
        }
        return sb.toString();
    }

    private static String toPem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }
}
