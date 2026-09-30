package net.hwyz.iov.cloud.framework.security.crypto.enrollment;

import net.hwyz.iov.cloud.framework.security.crypto.exception.InvalidCertificateRequestException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * PKCS#10 CSR 解析工具（step-ca OTT 授权用，FW-SEC-DSN-CR-008 §4.1）
 * <p>
 * step-ca JWK provisioner 要求 OTT 的 {@code sans} 授权覆盖 CSR 中的 SAN，否则 403 拒签。
 * 本工具从 CSR 的 {@code extensionRequest} 属性提取 SubjectAlternativeName，
 * 归一化为字符串列表（保留原始形态：URI 带 scheme、IP、DNS、email），
 * 交由 step-ca 侧按 scheme/格式重新分类，确保 OTT 授权与 CSR 一致。
 */
public final class CsrSanExtractor {

    private CsrSanExtractor() {
    }

    /**
     * 提取 CSR 中 SubjectAlternativeName 的全部条目，归一化为字符串列表（去重、保持顺序）。
     * <p>
     * URI 保留完整形态（含 scheme，如 {@code urn:ecu-uid:...}），DNS/IP/email 原样返回。
     * CSR 无 SAN 扩展时返回空列表（由调用方决定回退策略）。
     *
     * @param csr CSR（DER 或 PEM 编码）
     * @return SAN 字符串列表（可能为空）
     */
    public static List<String> extractSans(byte[] csr) {
        if (csr == null || csr.length == 0) {
            throw new InvalidCertificateRequestException("CSR must not be null or empty");
        }
        byte[] der = toDer(csr);
        try {
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(der);
            Extensions extensions = extractExtensions(request);
            if (extensions == null) {
                return List.of();
            }
            GeneralNames san = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
            if (san == null) {
                return List.of();
            }
            Set<String> result = new LinkedHashSet<>();
            for (GeneralName name : san.getNames()) {
                String value = stringValue(name);
                if (value != null && !value.isBlank()) {
                    result.add(value);
                }
            }
            return new ArrayList<>(result);
        } catch (InvalidCertificateRequestException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new InvalidCertificateRequestException("Failed to parse SANs from CSR", e);
        }
    }

    private static Extensions extractExtensions(PKCS10CertificationRequest request) {
        var attributes = request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes == null || attributes.length == 0) {
            return null;
        }
        var values = attributes[0].getAttributeValues();
        if (values == null || values.length == 0) {
            return null;
        }
        return Extensions.getInstance(values[0]);
    }

    /**
     * 将 GeneralName 归一化为 step-ca 可识别的字符串：
     * URI/DNS/email 取字符串值（URI 保留 scheme）；IP 取点分/冒号地址。
     * 其它类型（如 otherName、directoryName）不纳入 SAN 授权，返回 null。
     */
    private static String stringValue(GeneralName name) {
        return switch (name.getTagNo()) {
            case GeneralName.dNSName,
                 GeneralName.rfc822Name,
                 GeneralName.uniformResourceIdentifier -> {
                if (name.getName() instanceof org.bouncycastle.asn1.ASN1String s) {
                    yield s.getString();
                }
                yield null;
            }
            case GeneralName.iPAddress -> {
                byte[] ip = org.bouncycastle.asn1.ASN1OctetString.getInstance(name.getName()).getOctets();
                yield formatIp(ip);
            }
            default -> null;
        };
    }

    private static String formatIp(byte[] ip) {
        try {
            return java.net.InetAddress.getByAddress(ip).getHostAddress();
        } catch (Exception e) {
            throw new InvalidCertificateRequestException("Invalid IP address SAN in CSR", e);
        }
    }

    private static byte[] toDer(byte[] input) {
        String text = new String(input, java.nio.charset.StandardCharsets.US_ASCII).trim();
        if (text.startsWith("-----BEGIN")) {
            return CertPem.derFromPem(text);
        }
        return input;
    }
}
