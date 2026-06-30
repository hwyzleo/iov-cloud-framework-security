# FW-SEC-DSN-CR-001 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在现有framework-security-starter模块中新增加解密能力，提供信封加密/解密、keyId寻址、本地数据密钥缓存等功能。

**Architecture:** 在现有模块的net.hwyz.iov.cloud.framework.security.crypto包下组织所有加解密相关代码，包括CryptoTemplate、DeviceResolver、EnvelopeCodec、AeadCipher、KeyCache、KmsClient等组件。使用Feign客户端调用KMS和VMD/TSP服务，使用@ConfigurationProperties(prefix="crypto")绑定Nacos配置，使用Micrometer暴露指标，使用SLF4J记录审计日志。

**Tech Stack:** Java 17, Spring Boot 3.0.2, Spring Cloud 2022.0.0, Caffeine, Micrometer, OpenFeign, AES-256-GCM

---

## 文件结构

在开始实施前，需要创建以下目录结构：

```
src/main/java/net/hwyz/iov/cloud/framework/security/crypto/
├── CryptoTemplate.java
├── DefaultCryptoTemplate.java
├── model/
│   ├── EnvelopeHeader.java
│   ├── CipherPayload.java
│   ├── CachedDataKey.java
│   ├── BindingEntry.java
│   └── WrappedKey.java
├── codec/
│   └── EnvelopeCodec.java
├── cipher/
│   └── AeadCipher.java
├── resolver/
│   ├── DeviceResolver.java
│   └── DefaultDeviceResolver.java
├── client/
│   ├── KmsClient.java
│   └── FeignKmsClient.java
├── cache/
│   └── KeyCache.java
├── config/
│   ├── CryptoProperties.java
│   └── CryptoAutoConfiguration.java
├── exception/
│   ├── CryptoException.java
│   ├── DeviceUnboundException.java
│   ├── CryptoDependencyUnavailableException.java
│   ├── KeyRevokedException.java
│   └── IntegrityVerificationException.java
└── metrics/
    └── CryptoMetrics.java
```

---

### Task 1: 更新pom.xml依赖

**Files:**
- Modify: `pom.xml`

- [ ] **Step 1: 添加Caffeine依赖**

```xml
<!-- 缓存相关 -->
<dependency>
    <groupId>com.github.ben-manes.caffeine</groupId>
    <artifactId>caffeine</artifactId>
</dependency>
```

- [ ] **Step 2: 添加Micrometer依赖**

```xml
<!-- 可观测性相关 -->
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-core</artifactId>
</dependency>
```

- [ ] **Step 3: 验证依赖添加成功**

Run: `mvn dependency:tree | grep -E "caffeine|micrometer"`
Expected: 能看到caffeine和micrometer依赖

- [ ] **Step 4: 提交依赖变更**

```bash
git add pom.xml
git commit -m "deps: 添加Caffeine和Micrometer依赖"
```

---

### Task 2: 创建异常体系

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/exception/CryptoException.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/exception/DeviceUnboundException.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/exception/CryptoDependencyUnavailableException.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/exception/KeyRevokedException.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/exception/IntegrityVerificationException.java`

- [ ] **Step 1: 创建CryptoException基类**

```java
package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 加解密异常基类
 */
public abstract class CryptoException extends RuntimeException {

    private final Reason reason;

    public enum Reason {
        DEVICE_UNBOUND,
        DEPENDENCY_UNAVAILABLE,
        KEY_REVOKED,
        INTEGRITY_VERIFICATION_FAILED
    }

    public CryptoException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public CryptoException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
```

- [ ] **Step 2: 创建DeviceUnboundException**

```java
package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 设备未绑定异常
 */
public class DeviceUnboundException extends CryptoException {

    public DeviceUnboundException(String message) {
        super(Reason.DEVICE_UNBOUND, message);
    }

    public DeviceUnboundException(String message, Throwable cause) {
        super(Reason.DEVICE_UNBOUND, message, cause);
    }
}
```

- [ ] **Step 3: 创建CryptoDependencyUnavailableException**

```java
package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 依赖不可用异常（KMS/绑定服务不可达）
 */
public class CryptoDependencyUnavailableException extends CryptoException {

    public CryptoDependencyUnavailableException(String message) {
        super(Reason.DEPENDENCY_UNAVAILABLE, message);
    }

    public CryptoDependencyUnavailableException(String message, Throwable cause) {
        super(Reason.DEPENDENCY_UNAVAILABLE, message, cause);
    }
}
```

- [ ] **Step 4: 创建KeyRevokedException**

```java
package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 密钥失效/吊销异常
 */
public class KeyRevokedException extends CryptoException {

    public KeyRevokedException(String message) {
        super(Reason.KEY_REVOKED, message);
    }

    public KeyRevokedException(String message, Throwable cause) {
        super(Reason.KEY_REVOKED, message, cause);
    }
}
```

- [ ] **Step 5: 创建IntegrityVerificationException**

```java
package net.hwyz.iov.cloud.framework.security.crypto.exception;

/**
 * 完整性校验失败异常
 */
public class IntegrityVerificationException extends CryptoException {

    public IntegrityVerificationException(String message) {
        super(Reason.INTEGRITY_VERIFICATION_FAILED, message);
    }

    public IntegrityVerificationException(String message, Throwable cause) {
        super(Reason.INTEGRITY_VERIFICATION_FAILED, message, cause);
    }
}
```

- [ ] **Step 6: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 7: 提交异常体系**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/exception/
git commit -m "feat: 创建加解密异常体系"
```

---

### Task 3: 创建数据模型

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/model/EnvelopeHeader.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/model/CipherPayload.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/model/CachedDataKey.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/model/BindingEntry.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/model/WrappedKey.java`

- [ ] **Step 1: 创建EnvelopeHeader**

```java
package net.hwyz.iov.cloud.framework.security.crypto.model;

import lombok.Data;
import java.io.Serializable;

/**
 * 信封头
 */
@Data
public class EnvelopeHeader implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 版本号
     */
    private int ver;
    
    /**
     * 密钥ID
     */
    private String keyId;
    
    /**
     * 密钥版本
     */
    private int keyVersion;
    
    /**
     * 算法，如AES_256_GCM
     */
    private String alg;
    
    /**
     * 初始化向量（96-bit）
     */
    private byte[] iv;
}
```

- [ ] **Step 2: 创建CipherPayload**

```java
package net.hwyz.iov.cloud.framework.security.crypto.model;

import lombok.Data;
import java.io.Serializable;

/**
 * 密文线格式
 */
@Data
public class CipherPayload implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 魔数（2字节）
     */
    private byte[] magic;
    
    /**
     * 版本号（1字节）
     */
    private int ver;
    
    /**
     * 信封头长度（2字节）
     */
    private int headerLen;
    
    /**
     * 信封头
     */
    private EnvelopeHeader header;
    
    /**
     * 密文 + GCM tag（16字节）
     */
    private byte[] ciphertext;
}
```

- [ ] **Step 3: 创建CachedDataKey**

```java
package net.hwyz.iov.cloud.framework.security.crypto.model;

import lombok.Data;
import java.io.Serializable;
import java.time.Instant;

/**
 * 缓存项
 */
@Data
public class CachedDataKey implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 密钥ID
     */
    private String keyId;
    
    /**
     * 密钥版本
     */
    private int keyVersion;
    
    /**
     * 明文DEK（仅内存）
     */
    private transient byte[] dekPlaintext;
    
    /**
     * 业务域
     */
    private String bizDomain;
    
    /**
     * 设备SN
     */
    private String deviceSn;
    
    /**
     * 过期时间
     */
    private Instant expireAt;
}
```

- [ ] **Step 4: 创建BindingEntry**

```java
package net.hwyz.iov.cloud.framework.security.crypto.model;

import lombok.Data;
import java.io.Serializable;
import java.time.Instant;

/**
 * 绑定解析缓存
 */
@Data
public class BindingEntry implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * VIN
     */
    private String vin;
    
    /**
     * 器件类别
     */
    private String deviceCategory;
    
    /**
     * 设备SN
     */
    private String deviceSn;
    
    /**
     * 状态（ACTIVE/...）
     */
    private String status;
    
    /**
     * 过期时间
     */
    private Instant expireAt;
}
```

- [ ] **Step 5: 创建WrappedKey**

```java
package net.hwyz.iov.cloud.framework.security.crypto.model;

import lombok.Data;
import java.io.Serializable;

/**
 * KMS返回的包装密钥
 */
@Data
public class WrappedKey implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 密钥ID
     */
    private String keyId;
    
    /**
     * 密钥版本
     */
    private int keyVersion;
    
    /**
     * 包装后的DEK
     */
    private byte[] wrappedDek;
}
```

- [ ] **Step 6: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 7: 提交数据模型**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/model/
git commit -m "feat: 创建加解密数据模型"
```

---

### Task 4: 创建配置类

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/config/CryptoProperties.java`

- [ ] **Step 1: 创建CryptoProperties**

```java
package net.hwyz.iov.cloud.framework.security.crypto.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * 加解密配置属性
 */
@Data
@Component
@ConfigurationProperties(prefix = "crypto")
public class CryptoProperties {

    /**
     * KMS配置
     */
    private Kms kms = new Kms();

    /**
     * 密钥缓存配置
     */
    private KeyCache keyCache = new KeyCache();

    /**
     * 绑定缓存配置
     */
    private BindingCache bindingCache = new BindingCache();

    /**
     * AEAD算法
     */
    private String alg = "AES_256_GCM";

    /**
     * 业务域→器件类别路由表
     */
    private Map<String, String> deviceRouting = new HashMap<>();

    /**
     * 失败策略（CLOSED/OPEN）
     */
    private String failMode = "CLOSED";

    @Data
    public static class Kms {
        /**
         * KMS服务地址
         */
        private String endpoint;

        /**
         * 连接超时
         */
        private Duration connectTimeout = Duration.ofMillis(500);

        /**
         * 读超时
         */
        private Duration readTimeout = Duration.ofSeconds(1);

        /**
         * 重试次数
         */
        private int retryCount = 2;
    }

    @Data
    public static class KeyCache {
        /**
         * DEK本地缓存TTL
         */
        private Duration ttl = Duration.ofMinutes(10);

        /**
         * 缓存最大条目
         */
        private int maxSize = 10000;
    }

    @Data
    public static class BindingCache {
        /**
         * 绑定解析缓存TTL
         */
        private Duration ttl = Duration.ofMinutes(5);
    }
}
```

- [ ] **Step 2: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: 提交配置类**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/config/CryptoProperties.java
git commit -m "feat: 创建加解密配置类"
```

---

### Task 5: 创建SPI接口

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/client/KmsClient.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/resolver/DeviceResolver.java`

- [ ] **Step 1: 创建KmsClient接口**

```java
package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;

/**
 * KMS客户端接口
 */
public interface KmsClient {

    /**
     * 获取活跃数据密钥
     *
     * @param deviceSn  设备SN
     * @param bizDomain 业务域
     * @return 包装密钥
     */
    WrappedKey getActiveDataKey(String deviceSn, String bizDomain);

    /**
     * 根据keyId获取历史数据密钥
     *
     * @param keyId 密钥ID
     * @return 包装密钥
     */
    WrappedKey getDataKeyById(String keyId);

    /**
     * 解封包装密钥
     *
     * @param wrapped 包装密钥
     * @return 明文DEK
     */
    byte[] unwrap(WrappedKey wrapped);
}
```

- [ ] **Step 2: 创建DeviceResolver接口**

```java
package net.hwyz.iov.cloud.framework.security.crypto.resolver;

/**
 * 设备解析器接口
 */
public interface DeviceResolver {

    /**
     * 解析设备SN
     *
     * @param vin       VIN
     * @param bizDomain 业务域
     * @return 设备SN
     */
    String resolveDeviceSn(String vin, String bizDomain);
}
```

- [ ] **Step 3: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 4: 提交SPI接口**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/client/KmsClient.java
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/resolver/DeviceResolver.java
git commit -m "feat: 创建KmsClient和DeviceResolver SPI接口"
```

---

### Task 6: 创建信封编解码器

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/codec/EnvelopeCodec.java`

- [ ] **Step 1: 创建EnvelopeCodec**

```java
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
 */
@Component
public class EnvelopeCodec {

    private static final byte[] MAGIC = {(byte) 0xCF, (byte) 0x01};
    private static final int VERSION = 1;
    private static final int HEADER_LEN_SIZE = 2;

    /**
     * 编码信封头和密文
     *
     * @param header     信封头
     * @param ciphertext 密文 + tag
     * @return 编码后的字节数组
     */
    public byte[] encode(EnvelopeHeader header, byte[] ciphertext) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            
            // 写入魔数
            baos.write(MAGIC);
            
            // 写入版本号
            baos.write(VERSION);
            
            // 编码信封头
            byte[] headerBytes = encodeHeader(header);
            
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
        if (ver != VERSION) {
            throw new IntegrityVerificationException("Invalid cipher payload: unsupported version");
        }

        // 读取信封头长度
        int headerLen = buffer.getShort() & 0xFFFF;
        if (headerLen < 0 || headerLen > buffer.remaining()) {
            throw new IntegrityVerificationException("Invalid cipher payload: invalid header length");
        }

        // 读取信封头
        byte[] headerBytes = new byte[headerLen];
        buffer.get(headerBytes);
        EnvelopeHeader header = decodeHeader(headerBytes);

        // 读取密文 + tag
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        CipherPayload payload = new CipherPayload();
        payload.setMagic(magic);
        payload.setVer(ver);
        payload.setHeaderLen(headerLen);
        payload.setHeader(header);
        payload.setCiphertext(ciphertext);

        return payload;
    }

    /**
     * 编码信封头
     */
    private byte[] encodeHeader(EnvelopeHeader header) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            
            // 写入版本号
            baos.write(header.getVer());
            
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
            
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IntegrityVerificationException("Failed to encode header", e);
        }
    }

    /**
     * 解码信封头
     */
    private EnvelopeHeader decodeHeader(byte[] data) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.BIG_ENDIAN);

            EnvelopeHeader header = new EnvelopeHeader();

            // 读取版本号
            header.setVer(buffer.get() & 0xFF);

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

            return header;
        } catch (Exception e) {
            throw new IntegrityVerificationException("Failed to decode header", e);
        }
    }
}
```

- [ ] **Step 2: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: 提交信封编解码器**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/codec/EnvelopeCodec.java
git commit -m "feat: 创建信封编解码器"
```

---

### Task 7: 创建AEAD加密器

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/cipher/AeadCipher.java`

- [ ] **Step 1: 创建AeadCipher**

```java
package net.hwyz.iov.cloud.framework.security.crypto.cipher;

import net.hwyz.iov.cloud.framework.security.crypto.exception.IntegrityVerificationException;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AEAD加密器（AES-256-GCM）
 */
@Component
public class AeadCipher {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96-bit
    private static final int GCM_TAG_LENGTH = 128; // 128-bit tag

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * 生成随机IV
     *
     * @return IV字节数组
     */
    public byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * 加密
     *
     * @param plaintext 明文
     * @param dek       明文DEK
     * @param iv        初始化向量
     * @param aad       附加认证数据（信封头）
     * @return 密文 + tag
     */
    public byte[] encrypt(byte[] plaintext, byte[] dek, byte[] iv, byte[] aad) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(dek, ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

            if (aad != null) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new IntegrityVerificationException("Encryption failed", e);
        }
    }

    /**
     * 解密
     *
     * @param ciphertext 密文 + tag
     * @param dek        明文DEK
     * @param iv         初始化向量
     * @param aad        附加认证数据（信封头）
     * @return 明文
     */
    public byte[] decrypt(byte[] ciphertext, byte[] dek, byte[] iv, byte[] aad) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(dek, ALGORITHM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

            if (aad != null) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new IntegrityVerificationException("Decryption failed: integrity verification failed", e);
        }
    }
}
```

- [ ] **Step 2: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: 提交AEAD加密器**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/cipher/AeadCipher.java
git commit -m "feat: 创建AEAD加密器"
```

---

### Task 8: 创建密钥缓存

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/cache/KeyCache.java`

- [ ] **Step 1: 创建KeyCache**

```java
package net.hwyz.iov.cloud.framework.security.crypto.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.KeyRevokedException;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * 密钥缓存
 */
@Component
public class KeyCache {

    private final CryptoProperties properties;
    private final KmsClient kmsClient;

    private Cache<String, CachedDataKey> cache;

    public KeyCache(CryptoProperties properties, KmsClient kmsClient) {
        this.properties = properties;
        this.kmsClient = kmsClient;
    }

    @PostConstruct
    public void init() {
        this.cache = Caffeine.newBuilder()
                .maximumSize(properties.getKeyCache().getMaxSize())
                .expireAfterWrite(properties.getKeyCache().getTtl().toMillis(), TimeUnit.MILLISECONDS)
                .build();
    }

    /**
     * 获取数据密钥（按设备SN和业务域）
     *
     * @param deviceSn  设备SN
     * @param bizDomain 业务域
     * @return 缓存的数据密钥
     */
    public CachedDataKey get(String deviceSn, String bizDomain) {
        String cacheKey = buildCacheKey(deviceSn, bizDomain);
        CachedDataKey cached = cache.getIfPresent(cacheKey);

        if (cached != null && !cached.getExpireAt().isBefore(Instant.now())) {
            return cached;
        }

        // 缓存未命中或已过期，从KMS获取
        try {
            WrappedKey wrapped = kmsClient.getActiveDataKey(deviceSn, bizDomain);
            byte[] dekPlaintext = kmsClient.unwrap(wrapped);

            CachedDataKey dataKey = new CachedDataKey();
            dataKey.setKeyId(wrapped.getKeyId());
            dataKey.setKeyVersion(wrapped.getKeyVersion());
            dataKey.setDekPlaintext(dekPlaintext);
            dataKey.setBizDomain(bizDomain);
            dataKey.setDeviceSn(deviceSn);
            dataKey.setExpireAt(Instant.now().plus(properties.getKeyCache().getTtl()));

            cache.put(cacheKey, dataKey);
            return dataKey;
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get data key from KMS", e);
        }
    }

    /**
     * 获取数据密钥（按keyId）
     *
     * @param keyId      密钥ID
     * @param keyVersion 密钥版本
     * @return 缓存的数据密钥
     */
    public CachedDataKey get(String keyId, int keyVersion) {
        String cacheKey = buildCacheKey(keyId, keyVersion);
        CachedDataKey cached = cache.getIfPresent(cacheKey);

        if (cached != null && !cached.getExpireAt().isBefore(Instant.now())) {
            return cached;
        }

        // 缓存未命中或已过期，从KMS获取
        try {
            WrappedKey wrapped = kmsClient.getDataKeyById(keyId);
            if (wrapped == null) {
                throw new KeyRevokedException("Key not found or revoked: " + keyId);
            }

            byte[] dekPlaintext = kmsClient.unwrap(wrapped);

            CachedDataKey dataKey = new CachedDataKey();
            dataKey.setKeyId(wrapped.getKeyId());
            dataKey.setKeyVersion(wrapped.getKeyVersion());
            dataKey.setDekPlaintext(dekPlaintext);
            dataKey.setExpireAt(Instant.now().plus(properties.getKeyCache().getTtl()));

            cache.put(cacheKey, dataKey);
            return dataKey;
        } catch (KeyRevokedException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get data key from KMS", e);
        }
    }

    /**
     * 使缓存失效
     *
     * @param keyId 密钥ID
     */
    public void invalidate(String keyId) {
        cache.asMap().entrySet().removeIf(entry -> entry.getValue().getKeyId().equals(keyId));
    }

    private String buildCacheKey(String deviceSn, String bizDomain) {
        return deviceSn + ":" + bizDomain;
    }

    private String buildCacheKey(String keyId, int keyVersion) {
        return keyId + ":" + keyVersion;
    }
}
```

- [ ] **Step 2: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: 提交密钥缓存**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/cache/KeyCache.java
git commit -m "feat: 创建密钥缓存"
```

---

### Task 9: 创建Feign KMS客户端

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/client/FeignKmsClient.java`

- [ ] **Step 1: 创建FeignKmsClient**

```java
package net.hwyz.iov.cloud.framework.security.crypto.client;

import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.model.WrappedKey;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Feign KMS客户端实现
 */
@Component
public class FeignKmsClient implements KmsClient {

    private final CryptoProperties properties;
    private final KmsFeignClient kmsFeignClient;

    public FeignKmsClient(CryptoProperties properties, KmsFeignClient kmsFeignClient) {
        this.properties = properties;
        this.kmsFeignClient = kmsFeignClient;
    }

    @Override
    public WrappedKey getActiveDataKey(String deviceSn, String bizDomain) {
        try {
            DataKeyRequest request = new DataKeyRequest();
            request.setDeviceSn(deviceSn);
            request.setBizDomain(bizDomain);
            return kmsFeignClient.getActiveDataKey(request);
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get active data key from KMS", e);
        }
    }

    @Override
    public WrappedKey getDataKeyById(String keyId) {
        try {
            DataKeyByIdRequest request = new DataKeyByIdRequest();
            request.setKeyId(keyId);
            return kmsFeignClient.getDataKeyById(request);
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to get data key by ID from KMS", e);
        }
    }

    @Override
    public byte[] unwrap(WrappedKey wrapped) {
        try {
            UnwrapRequest request = new UnwrapRequest();
            request.setKeyId(wrapped.getKeyId());
            request.setKeyVersion(wrapped.getKeyVersion());
            request.setWrappedDek(wrapped.getWrappedDek());
            UnwrapResponse response = kmsFeignClient.unwrap(request);
            return response.getDekPlaintext();
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to unwrap key from KMS", e);
        }
    }

    @FeignClient(name = "kms-service", url = "${crypto.kms.endpoint}")
    public interface KmsFeignClient {

        @PostMapping("/transit/datakey")
        WrappedKey getActiveDataKey(@RequestBody DataKeyRequest request);

        @PostMapping("/transit/datakey/by-id")
        WrappedKey getDataKeyById(@RequestBody DataKeyByIdRequest request);

        @PostMapping("/transit/decrypt")
        UnwrapResponse unwrap(@RequestBody UnwrapRequest request);
    }

    @lombok.Data
    public static class DataKeyRequest {
        private String deviceSn;
        private String bizDomain;
    }

    @lombok.Data
    public static class DataKeyByIdRequest {
        private String keyId;
    }

    @lombok.Data
    public static class UnwrapRequest {
        private String keyId;
        private int keyVersion;
        private byte[] wrappedDek;
    }

    @lombok.Data
    public static class UnwrapResponse {
        private byte[] dekPlaintext;
    }
}
```

- [ ] **Step 2: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: 提交Feign KMS客户端**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/client/FeignKmsClient.java
git commit -m "feat: 创建Feign KMS客户端"
```

---

### Task 10: 创建设备解析器

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/resolver/DefaultDeviceResolver.java`

- [ ] **Step 1: 创建DefaultDeviceResolver**

```java
package net.hwyz.iov.cloud.framework.security.crypto.resolver;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import net.hwyz.iov.cloud.framework.security.crypto.config.CryptoProperties;
import net.hwyz.iov.cloud.framework.security.crypto.exception.CryptoDependencyUnavailableException;
import net.hwyz.iov.cloud.framework.security.crypto.exception.DeviceUnboundException;
import net.hwyz.iov.cloud.framework.security.crypto.model.BindingEntry;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 默认设备解析器实现
 */
@Component
public class DefaultDeviceResolver implements DeviceResolver {

    private final CryptoProperties properties;
    private final RestTemplate restTemplate;

    private Cache<String, BindingEntry> cache;

    public DefaultDeviceResolver(CryptoProperties properties) {
        this.properties = properties;
        this.restTemplate = new RestTemplate();
    }

    @PostConstruct
    public void init() {
        this.cache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(properties.getBindingCache().getTtl().toMillis(), TimeUnit.MILLISECONDS)
                .build();
    }

    @Override
    public String resolveDeviceSn(String vin, String bizDomain) {
        // 获取器件类别
        String deviceCategory = getDeviceCategory(bizDomain);

        // 查询缓存
        String cacheKey = buildCacheKey(vin, deviceCategory);
        BindingEntry cached = cache.getIfPresent(cacheKey);

        if (cached != null && !cached.getExpireAt().isBefore(Instant.now())) {
            if (!"ACTIVE".equals(cached.getStatus())) {
                throw new DeviceUnboundException("Device not active: " + vin);
            }
            return cached.getDeviceSn();
        }

        // 缓存未命中，查询VMD/TSP服务
        try {
            BindingEntry entry = queryBinding(vin, deviceCategory);
            if (entry == null || !"ACTIVE".equals(entry.getStatus())) {
                throw new DeviceUnboundException("Device not bound or not active: " + vin);
            }

            cache.put(cacheKey, entry);
            return entry.getDeviceSn();
        } catch (DeviceUnboundException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoDependencyUnavailableException("Failed to resolve device binding", e);
        }
    }

    private String getDeviceCategory(String bizDomain) {
        Map<String, String> routing = properties.getDeviceRouting();
        return routing.getOrDefault(bizDomain, routing.getOrDefault("default", "TBOX"));
    }

    private BindingEntry queryBinding(String vin, String deviceCategory) {
        // TODO: 实现VMD/TSP服务调用
        // 这里应该调用VMD/TSP服务的绑定查询接口
        // 暂时返回模拟数据
        BindingEntry entry = new BindingEntry();
        entry.setVin(vin);
        entry.setDeviceCategory(deviceCategory);
        entry.setDeviceSn("SN_" + vin); // 模拟数据
        entry.setStatus("ACTIVE");
        entry.setExpireAt(Instant.now().plus(properties.getBindingCache().getTtl()));
        return entry;
    }

    private String buildCacheKey(String vin, String deviceCategory) {
        return vin + ":" + deviceCategory;
    }
}
```

- [ ] **Step 2: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: 提交设备解析器**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/resolver/DefaultDeviceResolver.java
git commit -m "feat: 创建默认设备解析器实现"
```

---

### Task 11: 创建CryptoTemplate门面API

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/CryptoTemplate.java`
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/DefaultCryptoTemplate.java`

- [ ] **Step 1: 创建CryptoTemplate接口**

```java
package net.hwyz.iov.cloud.framework.security.crypto;

/**
 * 加解密门面API接口
 */
public interface CryptoTemplate {

    /**
     * 加密
     *
     * @param vin       VIN
     * @param bizDomain 业务域
     * @param plaintext 明文
     * @return 密文payload（包含信封头）
     */
    byte[] encrypt(String vin, String bizDomain, byte[] plaintext);

    /**
     * 解密
     *
     * @param cipherPayload 密文payload（包含信封头）
     * @return 明文
     */
    byte[] decrypt(byte[] cipherPayload);
}
```

- [ ] **Step 2: 创建DefaultCryptoTemplate**

```java
package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.springframework.stereotype.Component;

/**
 * CryptoTemplate默认实现
 */
@Component
public class DefaultCryptoTemplate implements CryptoTemplate {

    private final DeviceResolver deviceResolver;
    private final KeyCache keyCache;
    private final AeadCipher aeadCipher;
    private final EnvelopeCodec envelopeCodec;

    public DefaultCryptoTemplate(DeviceResolver deviceResolver, KeyCache keyCache,
                                 AeadCipher aeadCipher, EnvelopeCodec envelopeCodec) {
        this.deviceResolver = deviceResolver;
        this.keyCache = keyCache;
        this.aeadCipher = aeadCipher;
        this.envelopeCodec = envelopeCodec;
    }

    @Override
    public byte[] encrypt(String vin, String bizDomain, byte[] plaintext) {
        // 1. 解析设备SN
        String deviceSn = deviceResolver.resolveDeviceSn(vin, bizDomain);

        // 2. 获取数据密钥
        CachedDataKey dataKey = keyCache.get(deviceSn, bizDomain);

        // 3. 生成IV
        byte[] iv = aeadCipher.generateIv();

        // 4. 构建信封头
        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId(dataKey.getKeyId());
        header.setKeyVersion(dataKey.getKeyVersion());
        header.setAlg("AES_256_GCM");
        header.setIv(iv);

        // 5. 编码信封头作为AAD
        byte[] aad = envelopeCodec.encode(header, new byte[0]);

        // 6. 加密
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dataKey.getDekPlaintext(), iv, aad);

        // 7. 返回完整payload
        return envelopeCodec.encode(header, ciphertext);
    }

    @Override
    public byte[] decrypt(byte[] cipherPayload) {
        // 1. 解码信封头
        CipherPayload payload = envelopeCodec.decode(cipherPayload);
        EnvelopeHeader header = payload.getHeader();

        // 2. 获取数据密钥
        CachedDataKey dataKey = keyCache.get(header.getKeyId(), header.getKeyVersion());

        // 3. 编码信封头作为AAD
        byte[] aad = envelopeCodec.encode(header, new byte[0]);

        // 4. 解密
        return aeadCipher.decrypt(payload.getCiphertext(), dataKey.getDekPlaintext(), header.getIv(), aad);
    }
}
```

- [ ] **Step 3: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 4: 提交CryptoTemplate**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/CryptoTemplate.java
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/DefaultCryptoTemplate.java
git commit -m "feat: 创建CryptoTemplate门面API"
```

---

### Task 12: 创建可观测性组件

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/metrics/CryptoMetrics.java`

- [ ] **Step 1: 创建CryptoMetrics**

```java
package net.hwyz.iov.cloud.framework.security.crypto.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * 加解密指标收集
 */
@Component
public class CryptoMetrics {

    private final Counter encryptCounter;
    private final Counter decryptCounter;
    private final Counter kmsCallCounter;
    private final Counter errorCounter;
    private final Timer encryptTimer;
    private final Timer decryptTimer;
    private final Timer kmsCallTimer;

    public CryptoMetrics(MeterRegistry meterRegistry) {
        this.encryptCounter = Counter.builder("crypto.encrypt.count")
                .description("加密次数")
                .register(meterRegistry);

        this.decryptCounter = Counter.builder("crypto.decrypt.count")
                .description("解密次数")
                .register(meterRegistry);

        this.kmsCallCounter = Counter.builder("crypto.kms.call.count")
                .description("KMS调用次数")
                .register(meterRegistry);

        this.errorCounter = Counter.builder("crypto.error.count")
                .description("错误计数")
                .register(meterRegistry);

        this.encryptTimer = Timer.builder("crypto.encrypt.duration")
                .description("加密时延")
                .register(meterRegistry);

        this.decryptTimer = Timer.builder("crypto.decrypt.duration")
                .description("解密时延")
                .register(meterRegistry);

        this.kmsCallTimer = Timer.builder("crypto.kms.call.duration")
                .description("KMS调用时延")
                .register(meterRegistry);
    }

    /**
     * 记录加密操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordEncrypt(long duration) {
        encryptCounter.increment();
        encryptTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录解密操作
     *
     * @param duration 耗时（毫秒）
     */
    public void recordDecrypt(long duration) {
        decryptCounter.increment();
        decryptTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录KMS调用
     *
     * @param duration 耗时（毫秒）
     */
    public void recordKmsCall(long duration) {
        kmsCallCounter.increment();
        kmsCallTimer.record(duration, TimeUnit.MILLISECONDS);
    }

    /**
     * 记录错误
     */
    public void recordError() {
        errorCounter.increment();
    }
}
```

- [ ] **Step 2: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: 提交可观测性组件**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/metrics/CryptoMetrics.java
git commit -m "feat: 创建加解密可观测性组件"
```

---

### Task 13: 创建自动配置

**Files:**
- Create: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/config/CryptoAutoConfiguration.java`

- [ ] **Step 1: 创建CryptoAutoConfiguration**

```java
package net.hwyz.iov.cloud.framework.security.crypto.config;

import net.hwyz.iov.cloud.framework.security.crypto.CryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.DefaultCryptoTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.client.FeignKmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.client.KmsClient;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DefaultDeviceResolver;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 加解密自动配置
 */
@AutoConfiguration
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public EnvelopeCodec envelopeCodec() {
        return new EnvelopeCodec();
    }

    @Bean
    @ConditionalOnMissingBean
    public AeadCipher aeadCipher() {
        return new AeadCipher();
    }

    @Bean
    @ConditionalOnMissingBean
    public KmsClient kmsClient(CryptoProperties properties, FeignKmsClient.KmsFeignClient kmsFeignClient) {
        return new FeignKmsClient(properties, kmsFeignClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public DeviceResolver deviceResolver(CryptoProperties properties) {
        return new DefaultDeviceResolver(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public KeyCache keyCache(CryptoProperties properties, KmsClient kmsClient) {
        return new KeyCache(properties, kmsClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public CryptoMetrics cryptoMetrics(io.micrometer.core.instrument.MeterRegistry meterRegistry) {
        return new CryptoMetrics(meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public CryptoTemplate cryptoTemplate(DeviceResolver deviceResolver, KeyCache keyCache,
                                         AeadCipher aeadCipher, EnvelopeCodec envelopeCodec) {
        return new DefaultCryptoTemplate(deviceResolver, keyCache, aeadCipher, envelopeCodec);
    }
}
```

- [ ] **Step 2: 创建spring.factories文件**

Create file: `src/main/resources/META-INF/spring.factories`

```properties
org.springframework.boot.autoconfigure.EnableAutoConfiguration=\
net.hwyz.iov.cloud.framework.security.crypto.config.CryptoAutoConfiguration
```

- [ ] **Step 3: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 4: 提交自动配置**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/config/CryptoAutoConfiguration.java
git add src/main/resources/META-INF/spring.factories
git commit -m "feat: 创建加解密自动配置"
```

---

### Task 14: 更新CryptoTemplate集成可观测性

**Files:**
- Modify: `src/main/java/net/hwyz/iov/cloud/framework/security/crypto/DefaultCryptoTemplate.java`

- [ ] **Step 1: 更新DefaultCryptoTemplate集成指标**

```java
package net.hwyz.iov.cloud.framework.security.crypto;

import net.hwyz.iov.cloud.framework.security.crypto.cache.KeyCache;
import net.hwyz.iov.cloud.framework.security.crypto.cipher.AeadCipher;
import net.hwyz.iov.cloud.framework.security.crypto.codec.EnvelopeCodec;
import net.hwyz.iov.cloud.framework.security.crypto.metrics.CryptoMetrics;
import net.hwyz.iov.cloud.framework.security.crypto.model.CachedDataKey;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import net.hwyz.iov.cloud.framework.security.crypto.resolver.DeviceResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * CryptoTemplate默认实现
 */
@Component
public class DefaultCryptoTemplate implements CryptoTemplate {

    private static final Logger log = LoggerFactory.getLogger(DefaultCryptoTemplate.class);

    private final DeviceResolver deviceResolver;
    private final KeyCache keyCache;
    private final AeadCipher aeadCipher;
    private final EnvelopeCodec envelopeCodec;
    private final CryptoMetrics cryptoMetrics;

    public DefaultCryptoTemplate(DeviceResolver deviceResolver, KeyCache keyCache,
                                 AeadCipher aeadCipher, EnvelopeCodec envelopeCodec,
                                 CryptoMetrics cryptoMetrics) {
        this.deviceResolver = deviceResolver;
        this.keyCache = keyCache;
        this.aeadCipher = aeadCipher;
        this.envelopeCodec = envelopeCodec;
        this.cryptoMetrics = cryptoMetrics;
    }

    @Override
    public byte[] encrypt(String vin, String bizDomain, byte[] plaintext) {
        long startTime = System.currentTimeMillis();
        try {
            // 1. 解析设备SN
            String deviceSn = deviceResolver.resolveDeviceSn(vin, bizDomain);

            // 2. 获取数据密钥
            CachedDataKey dataKey = keyCache.get(deviceSn, bizDomain);

            // 3. 生成IV
            byte[] iv = aeadCipher.generateIv();

            // 4. 构建信封头
            EnvelopeHeader header = new EnvelopeHeader();
            header.setVer(1);
            header.setKeyId(dataKey.getKeyId());
            header.setKeyVersion(dataKey.getKeyVersion());
            header.setAlg("AES_256_GCM");
            header.setIv(iv);

            // 5. 编码信封头作为AAD
            byte[] aad = envelopeCodec.encode(header, new byte[0]);

            // 6. 加密
            byte[] ciphertext = aeadCipher.encrypt(plaintext, dataKey.getDekPlaintext(), iv, aad);

            // 7. 返回完整payload
            byte[] result = envelopeCodec.encode(header, ciphertext);

            // 记录审计日志
            long duration = System.currentTimeMillis() - startTime;
            log.info("加密成功: vin={}, bizDomain={}, keyId={}, duration={}ms", 
                    vin, bizDomain, dataKey.getKeyId(), duration);
            cryptoMetrics.recordEncrypt(duration);

            return result;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("加密失败: vin={}, bizDomain={}", vin, bizDomain, e);
            throw e;
        }
    }

    @Override
    public byte[] decrypt(byte[] cipherPayload) {
        long startTime = System.currentTimeMillis();
        try {
            // 1. 解码信封头
            CipherPayload payload = envelopeCodec.decode(cipherPayload);
            EnvelopeHeader header = payload.getHeader();

            // 2. 获取数据密钥
            CachedDataKey dataKey = keyCache.get(header.getKeyId(), header.getKeyVersion());

            // 3. 编码信封头作为AAD
            byte[] aad = envelopeCodec.encode(header, new byte[0]);

            // 4. 解密
            byte[] result = aeadCipher.decrypt(payload.getCiphertext(), dataKey.getDekPlaintext(), header.getIv(), aad);

            // 记录审计日志
            long duration = System.currentTimeMillis() - startTime;
            log.info("解密成功: keyId={}, keyVersion={}, duration={}ms", 
                    header.getKeyId(), header.getKeyVersion(), duration);
            cryptoMetrics.recordDecrypt(duration);

            return result;
        } catch (Exception e) {
            cryptoMetrics.recordError();
            log.error("解密失败", e);
            throw e;
        }
    }
}
```

- [ ] **Step 2: 验证编译通过**

Run: `mvn compile`
Expected: BUILD SUCCESS

- [ ] **Step 3: 提交更新**

```bash
git add src/main/java/net/hwyz/iov/cloud/framework/security/crypto/DefaultCryptoTemplate.java
git commit -m "feat: 更新CryptoTemplate集成可观测性"
```

---

### Task 15: 创建单元测试

**Files:**
- Create: `src/test/java/net/hwyz/iov/cloud/framework/security/crypto/codec/EnvelopeCodecTest.java`
- Create: `src/test/java/net/hwyz/iov/cloud/framework/security/crypto/cipher/AeadCipherTest.java`

- [ ] **Step 1: 创建EnvelopeCodecTest**

```java
package net.hwyz.iov.cloud.framework.security.crypto.codec;

import net.hwyz.iov.cloud.framework.security.crypto.exception.IntegrityVerificationException;
import net.hwyz.iov.cloud.framework.security.crypto.model.CipherPayload;
import net.hwyz.iov.cloud.framework.security.crypto.model.EnvelopeHeader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EnvelopeCodecTest {

    private EnvelopeCodec envelopeCodec;

    @BeforeEach
    void setUp() {
        envelopeCodec = new EnvelopeCodec();
    }

    @Test
    void testEncodeAndDecode() {
        // Given
        EnvelopeHeader header = new EnvelopeHeader();
        header.setVer(1);
        header.setKeyId("test-key-id");
        header.setKeyVersion(1);
        header.setAlg("AES_256_GCM");
        header.setIv(new byte[12]);

        byte[] ciphertext = new byte[]{1, 2, 3, 4, 5};

        // When
        byte[] encoded = envelopeCodec.encode(header, ciphertext);
        CipherPayload decoded = envelopeCodec.decode(encoded);

        // Then
        assertNotNull(decoded);
        assertEquals(1, decoded.getVer());
        assertEquals(header.getKeyId(), decoded.getHeader().getKeyId());
        assertEquals(header.getKeyVersion(), decoded.getHeader().getKeyVersion());
        assertEquals(header.getAlg(), decoded.getHeader().getAlg());
        assertArrayEquals(ciphertext, decoded.getCiphertext());
    }

    @Test
    void testDecodeInvalidMagic() {
        // Given
        byte[] invalidData = new byte[]{0, 0, 1, 0, 0};

        // When & Then
        assertThrows(IntegrityVerificationException.class, () -> {
            envelopeCodec.decode(invalidData);
        });
    }

    @Test
    void testDecodeTooShort() {
        // Given
        byte[] tooShort = new byte[]{(byte) 0xCF, 0x01};

        // When & Then
        assertThrows(IntegrityVerificationException.class, () -> {
            envelopeCodec.decode(tooShort);
        });
    }
}
```

- [ ] **Step 2: 创建AeadCipherTest**

```java
package net.hwyz.iov.cloud.framework.security.crypto.cipher;

import net.hwyz.iov.cloud.framework.security.crypto.exception.IntegrityVerificationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class AeadCipherTest {

    private AeadCipher aeadCipher;

    @BeforeEach
    void setUp() {
        aeadCipher = new AeadCipher();
    }

    @Test
    void testEncryptAndDecrypt() {
        // Given
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] dek = new byte[32]; // 256-bit key
        new SecureRandom().nextBytes(dek);
        byte[] iv = aeadCipher.generateIv();
        byte[] aad = "test-aad".getBytes();

        // When
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dek, iv, aad);
        byte[] decrypted = aeadCipher.decrypt(ciphertext, dek, iv, aad);

        // Then
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testDecryptWithWrongKey() {
        // Given
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] dek = new byte[32];
        new SecureRandom().nextBytes(dek);
        byte[] wrongDek = new byte[32];
        new SecureRandom().nextBytes(wrongDek);
        byte[] iv = aeadCipher.generateIv();
        byte[] aad = "test-aad".getBytes();

        // When
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dek, iv, aad);

        // Then
        assertThrows(IntegrityVerificationException.class, () -> {
            aeadCipher.decrypt(ciphertext, wrongDek, iv, aad);
        });
    }

    @Test
    void testDecryptWithTamperedCiphertext() {
        // Given
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] dek = new byte[32];
        new SecureRandom().nextBytes(dek);
        byte[] iv = aeadCipher.generateIv();
        byte[] aad = "test-aad".getBytes();

        // When
        byte[] ciphertext = aeadCipher.encrypt(plaintext, dek, iv, aad);
        ciphertext[0] ^= 1; // Tamper with ciphertext

        // Then
        assertThrows(IntegrityVerificationException.class, () -> {
            aeadCipher.decrypt(ciphertext, dek, iv, aad);
        });
    }
}
```

- [ ] **Step 3: 运行测试**

Run: `mvn test`
Expected: All tests pass

- [ ] **Step 4: 提交单元测试**

```bash
git add src/test/java/net/hwyz/iov/cloud/framework/security/crypto/
git commit -m "test: 添加信封编解码器和AEAD加密器单元测试"
```

---

## 执行选项

**计划完成并保存到 `docs/superpowers/plans/2026-06-30-crypto-design.md`。两种执行方式：**

**1. Subagent-Driven (推荐)** - 我为每个任务分发新的子代理，任务间进行审查，快速迭代

**2. Inline Execution** - 在本会话中使用executing-plans执行任务，批量执行并设置检查点

**选择哪种方式？**
