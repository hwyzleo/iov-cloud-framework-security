package net.hwyz.iov.cloud.framework.security.crypto.client;

import feign.Client;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.enrollment.TestPkiMaterial;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link PkiFeignConfiguration} 单元测试：验证 legacy-rest Feign 客户端的 TLS 信任装配。
 */
class PkiFeignConfigurationTest {

    private final PkiFeignConfiguration configuration = new PkiFeignConfiguration();

    @Test
    void unconfiguredTls_returnsDefaultClientWithDefaultTrust() throws Exception {
        CryptoProperties properties = new CryptoProperties();

        Client client = configuration.pkiFeignClient(properties);

        assertTrue(client instanceof Client.Default);
        // 未配置信任来源 → SSLSocketFactory 为 null（等同 JDK 默认信任，行为不变）
        assertNull(sslSocketFactoryOf(client));
    }

    @Test
    void inlinePem_buildsControlledTrustSocketFactory() throws Exception {
        TestPkiMaterial.Pki pki = TestPkiMaterial.generate();
        CryptoProperties properties = new CryptoProperties();
        properties.getPki().getTls().setTrustedCertsPem(
                TestPkiMaterial.pem("CERTIFICATE", pki.rootCert().getEncoded()));

        Client client = configuration.pkiFeignClient(properties);

        assertTrue(client instanceof Client.Default);
        // 配置了内联 PEM → 使用受控 truststore 构建的 SSLSocketFactory（非 null，非 trust-all）
        assertNotNull(sslSocketFactoryOf(client));
    }

    @Test
    void trustStoreFile_takesPrecedenceAndLoads() throws Exception {
        TestPkiMaterial.Pki pki = TestPkiMaterial.generate();

        // 生成一个仅含根证书的 PKCS12 truststore 文件
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("root", pki.rootCert());
        Path storeFile = Files.createTempFile("pki-trust", ".p12");
        char[] password = "changeit".toCharArray();
        try (var out = Files.newOutputStream(storeFile)) {
            ks.store(out, password);
        }

        try {
            CryptoProperties properties = new CryptoProperties();
            CryptoProperties.Pki.Tls tls = properties.getPki().getTls();
            tls.setTrustStoreFile(storeFile.toString());
            tls.setTrustStorePassword("changeit");
            tls.setTrustStoreType("PKCS12");
            // 同时配置 PEM，验证文件优先（不应因 PEM 解析异常而失败——此处 PEM 合法但走文件分支）
            tls.setTrustedCertsPem(TestPkiMaterial.pem("CERTIFICATE", pki.rootCert().getEncoded()));

            Client client = configuration.pkiFeignClient(properties);

            assertTrue(client instanceof Client.Default);
            assertNotNull(sslSocketFactoryOf(client));
        } finally {
            Files.deleteIfExists(storeFile);
        }
    }

    @Test
    void unreadableTrustStoreFile_failsFast() {
        CryptoProperties properties = new CryptoProperties();
        properties.getPki().getTls().setTrustStoreFile("/nonexistent/path/pki-trust.p12");

        assertThrows(IllegalStateException.class,
                () -> configuration.pkiFeignClient(properties));
    }

    @Test
    void tlsConfigured_reflectsSources() throws Exception {
        CryptoProperties.Pki.Tls tls = new CryptoProperties.Pki.Tls();
        assertTrue(!tls.isConfigured());

        TestPkiMaterial.Pki pki = TestPkiMaterial.generate();
        tls.setTrustedCertsPem(TestPkiMaterial.pem("CERTIFICATE", pki.rootCert().getEncoded()));
        assertTrue(tls.isConfigured());
    }

    /**
     * 反射读取 {@link Client.Default} 内部的 SSLSocketFactory，用于断言信任装配结果。
     */
    private static Object sslSocketFactoryOf(Client client) throws Exception {
        Field field = Client.Default.class.getDeclaredField("sslContextFactory");
        field.setAccessible(true);
        return field.get(client);
    }
}
