package net.hwyz.iov.cloud.framework.security.crypto.client;

import feign.Client;
import feign.RequestInterceptor;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.CertPem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * PKI Feign客户端配置
 * <p>
 * 作为 {@code @FeignClient(name = "pki-service")} 的专属配置，作用域仅限该 Feign 客户端：
 * <ul>
 *   <li>为 PKI 请求添加认证请求头；</li>
 *   <li>按 {@code crypto.pki.tls.*} 构建仅信任指定根/CA 的 {@link Client}
 *       （受控 truststore，禁 trust-all），使 legacy-rest provider 的 HTTPS 调用
 *       不依赖 JVM 全局 cacerts。</li>
 * </ul>
 */
public class PkiFeignConfiguration {

    private static final Logger log = LoggerFactory.getLogger(PkiFeignConfiguration.class);

    @Bean
    @ConditionalOnProperty(prefix = "crypto.pki", name = "token")
    public RequestInterceptor pkiRequestInterceptor(CryptoProperties properties) {
        return requestTemplate -> {
            String token = properties.getPki().getToken();
            if (token != null && !token.isEmpty()) {
                requestTemplate.header("Authorization", "Bearer " + token);
            }
        };
    }

    /**
     * PKI Feign HTTP 客户端。
     * <p>
     * 配置了 {@code crypto.pki.tls.*} 信任来源时，使用仅信任该来源的 {@link SSLSocketFactory}
     * （受控 truststore，保留默认 hostname 校验）；否则退回 JDK 默认信任（行为不变）。
     */
    @Bean
    public Client pkiFeignClient(CryptoProperties properties) {
        CryptoProperties.Pki.Tls tls = properties.getPki().getTls();
        if (tls == null || !tls.isConfigured()) {
            log.debug("PKI Feign 未配置 crypto.pki.tls.*，使用 JDK 默认信任");
            return new Client.Default(null, null);
        }
        SSLSocketFactory socketFactory = buildSocketFactory(tls);
        log.info("PKI Feign 已启用受控 truststore（禁 trust-all）: source={}",
                tls.getTrustStoreFile() != null && !tls.getTrustStoreFile().isBlank()
                        ? "trustStoreFile" : "trustedCertsPem");
        // 保留默认 HostnameVerifier：服务端证书 SAN 必须匹配请求主机名
        return new Client.Default(socketFactory, null);
    }

    private SSLSocketFactory buildSocketFactory(CryptoProperties.Pki.Tls tls) {
        try {
            KeyStore trustStore = loadTrustStore(tls);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx.getSocketFactory();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build PKI Feign TLS trust context", e);
        }
    }

    /**
     * 加载信任材料为 KeyStore。{@code trustStoreFile} 优先，其次内联 {@code trustedCertsPem}。
     */
    private KeyStore loadTrustStore(CryptoProperties.Pki.Tls tls) throws Exception {
        String file = tls.getTrustStoreFile();
        if (file != null && !file.isBlank()) {
            Path path = Path.of(file);
            if (!Files.isReadable(path)) {
                throw new IllegalStateException(
                        "crypto.pki.tls.trust-store-file is not readable: " + path);
            }
            KeyStore ks = KeyStore.getInstance(tls.getTrustStoreType());
            char[] password = tls.getTrustStorePassword() == null
                    ? null : tls.getTrustStorePassword().toCharArray();
            try (InputStream in = Files.newInputStream(path)) {
                ks.load(in, password);
            }
            return ks;
        }

        // 内联 PEM bundle → 受控 truststore
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        List<byte[]> ders = CertPem.parsePemBundle(tls.getTrustedCertsPem());
        int index = 0;
        for (byte[] der : ders) {
            X509Certificate cert = CertPem.parseCertificate(der);
            ks.setCertificateEntry("pki-trust-" + (index++), cert);
        }
        return ks;
    }
}
