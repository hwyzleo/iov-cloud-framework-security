# FW-SEC-DSN-CR-001 设计实现方案

## 1. 概述

基于设计变更FW-SEC-DSN-CR-001，在现有`framework-security-starter`模块中新增加解密能力，提供信封加密/解密、keyId寻址、本地数据密钥缓存等功能。

## 2. 架构设计

### 2.1 代码组织结构

在现有模块的`net.hwyz.iov.cloud.framework.security.crypto`包下组织所有加解密相关代码：

```
net.hwyz.iov.cloud.framework.security.crypto/
├── CryptoTemplate.java                    # 加解密门面API接口
├── DefaultCryptoTemplate.java             # CryptoTemplate默认实现
├── model/                                 # 数据模型
│   ├── EnvelopeHeader.java                # 信封头
│   ├── CipherPayload.java                 # 密文线格式
│   ├── CachedDataKey.java                 # 缓存项
│   ├── BindingEntry.java                  # 绑定解析缓存
│   └── WrappedKey.java                    # KMS返回的包装密钥
├── codec/                                 # 编解码器
│   └── EnvelopeCodec.java                 # 信封编解码器
├── cipher/                                # 加密器
│   └── AeadCipher.java                    # AEAD加密器
├── resolver/                              # 设备解析器
│   ├── DeviceResolver.java                # 设备解析器接口
│   └── DefaultDeviceResolver.java         # 默认实现
├── client/                                # 外部客户端
│   ├── KmsClient.java                     # KMS客户端接口
│   └── FeignKmsClient.java               # Feign实现
├── cache/                                 # 缓存
│   └── KeyCache.java                      # 密钥缓存
├── config/                                # 配置
│   ├── CryptoProperties.java              # 配置属性
│   └── CryptoAutoConfiguration.java       # 自动配置
├── exception/                             # 异常
│   ├── CryptoException.java               # 基类
│   ├── DeviceUnboundException.java        # 设备未绑定
│   ├── CryptoDependencyUnavailableException.java  # 依赖不可用
│   ├── KeyRevokedException.java           # 密钥失效
│   └── IntegrityVerificationException.java # 完整性校验失败
└── metrics/                               # 可观测性
    └── CryptoMetrics.java                 # 指标收集
```

### 2.2 组件关系

```
业务代码 → CryptoTemplate → DeviceResolver → VMD/TSP
                ↓
           KeyCache → KmsClient → KMS
                ↓
           AeadCipher → EnvelopeCodec
```

## 3. 数据模型设计

### 3.1 EnvelopeHeader（信封头）

```java
@Data
public class EnvelopeHeader {
    private int ver;           // 版本号
    private String keyId;      // 密钥ID
    private int keyVersion;    // 密钥版本
    private String alg;        // 算法，如AES_256_GCM
    private byte[] iv;         // 初始化向量（96-bit）
}
```

### 3.2 CipherPayload（密文线格式）

```java
@Data
public class CipherPayload {
    private byte[] magic;      // 魔数（2字节）
    private int ver;           // 版本号（1字节）
    private int headerLen;     // 信封头长度（2字节）
    private EnvelopeHeader header;  // 信封头
    private byte[] ciphertext; // 密文 + GCM tag（16字节）
}
```

### 3.3 CachedDataKey（缓存项）

```java
@Data
public class CachedDataKey {
    private String keyId;          // 密钥ID
    private int keyVersion;        // 密钥版本
    private byte[] dekPlaintext;   // 明文DEK（仅内存）
    private String bizDomain;      // 业务域
    private String deviceSn;       // 设备SN
    private Instant expireAt;      // 过期时间
}
```

### 3.4 BindingEntry（绑定解析缓存）

```java
@Data
public class BindingEntry {
    private String vin;            // VIN
    private String deviceCategory; // 器件类别
    private String deviceSn;       // 设备SN
    private String status;         // 状态（ACTIVE/...）
    private Instant expireAt;      // 过期时间
}
```

### 3.5 WrappedKey（KMS返回的包装密钥）

```java
@Data
public class WrappedKey {
    private String keyId;          // 密钥ID
    private int keyVersion;        // 密钥版本
    private byte[] wrappedDek;     // 包装后的DEK
}
```

## 4. 核心流程设计

### 4.1 下行加密流程

```
encrypt(vin, bizDomain, plaintext)
    ↓
DeviceResolver.resolveDeviceSn(vin, bizDomain)
    ↓
KeyCache.get(deviceSn, bizDomain)
    ↓
AeadCipher.encrypt(plaintext, dek, iv)
    ↓
EnvelopeCodec.encode(header, ciphertext)
    ↓
返回cipherPayload
```

### 4.2 上行解密流程

```
decrypt(cipherPayload)
    ↓
EnvelopeCodec.decode(cipherPayload)
    ↓
KeyCache.get(keyId, keyVersion)
    ↓
AeadCipher.decrypt(ciphertext, dek, iv, aad)
    ↓
返回plaintext
```

### 4.3 密钥轮换兼容

- 新流量：DeviceResolver → (deviceSn, bizDomain) → KMS取当前活跃keyId/keyVersion加密
- 旧密文：解密始终以信封头携带的keyId/keyVersion反向定位
- 缓存未命中：按keyId回源KMS
- 吊销：KMS标记keyId失效后，本地缓存于TTL到期收敛

## 5. API和配置契约设计

### 5.1 CryptoTemplate接口

```java
public interface CryptoTemplate {
    byte[] encrypt(String vin, String bizDomain, byte[] plaintext);
    byte[] decrypt(byte[] cipherPayload);
}
```

### 5.2 异常体系

```java
public abstract class CryptoException extends RuntimeException {
    // 携带语义枚举Reason
}

public class DeviceUnboundException extends CryptoException {
    // 未绑定/设备未知
}

public class CryptoDependencyUnavailableException extends CryptoException {
    // KMS/绑定不可达，fail-closed
}

public class KeyRevokedException extends CryptoException {
    // keyId失效/吊销
}

public class IntegrityVerificationException extends CryptoException {
    // AEAD验签失败/篡改
}
```

### 5.3 SPI接口

```java
public interface KmsClient {
    WrappedKey getActiveDataKey(String deviceSn, String bizDomain);
    WrappedKey getDataKeyById(String keyId);
    byte[] unwrap(WrappedKey wrapped);
}

public interface DeviceResolver {
    String resolveDeviceSn(String vin, String bizDomain);
}
```

### 5.4 配置项

```yaml
crypto:
  kms:
    endpoint: http://kms-service:8200  # KMS服务地址
  key-cache:
    ttl: 10m                           # DEK本地缓存TTL
    max-size: 10000                    # 缓存最大条目
  binding-cache:
    ttl: 5m                            # 绑定解析缓存TTL
  alg: AES_256_GCM                     # AEAD算法
  device-routing:                      # 业务域→器件类别路由表（v1恒为TBOX）
    default: TBOX                      # 默认路由
  fail-mode: CLOSED                    # 失败策略（固定fail-closed）
```

## 6. 依赖和影响分析

### 6.1 新增依赖

在pom.xml中添加：

```xml
<!-- 缓存相关 -->
<dependency>
    <groupId>com.github.ben-manes.caffeine</groupId>
    <artifactId>caffeine</artifactId>
</dependency>

<!-- 可观测性相关 -->
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-core</artifactId>
</dependency>
```

### 6.2 不影响现有功能

- 新增crypto子包，不修改现有认证授权代码
- 现有SecurityUtils、AuthLogic等类保持不变
- 现有拦截器、注解、切面等保持不变

### 6.3 业务服务使用方式

```xml
<!-- 引入依赖 -->
<dependency>
    <groupId>net.hwyz.iov.cloud.framework</groupId>
    <artifactId>framework-security-starter</artifactId>
</dependency>
```

```java
// 注入使用
@Autowired
private CryptoTemplate cryptoTemplate;

// 加密
byte[] cipherPayload = cryptoTemplate.encrypt(vin, bizDomain, plaintext);

// 解密
byte[] plaintext = cryptoTemplate.decrypt(cipherPayload);
```

### 6.4 外部服务依赖

1. **KMS服务**：需要提供以下能力：
   - 按(device_sn, 业务域)取活跃DEK
   - 按keyId取历史DEK
   - Unwrap能力
   - 密钥轮换/吊销能力

2. **VMD/TSP服务**：需要提供：
   - (VIN, 器件类别) → device_sn绑定查询接口

## 7. 可观测性设计

### 7.1 Micrometer指标

- `crypto.encrypt.count` - 加密次数
- `crypto.decrypt.count` - 解密次数
- `crypto.encrypt.duration` - 加密时延
- `crypto.decrypt.duration` - 解密时延
- `crypto.cache.hit.rate` - 缓存命中率
- `crypto.kms.call.count` - KMS调用次数
- `crypto.kms.call.duration` - KMS调用时延
- `crypto.error.count` - 错误计数

### 7.2 审计日志

使用SLF4J记录审计日志，包含：
- device_sn
- 业务域
- keyId
- 操作（加密/解密）
- 结果（成功/失败）
- 耗时
- 不记录明文业务数据与明文密钥

## 8. 实施计划

### 8.1 第一阶段：基础框架

1. 创建crypto包结构
2. 实现数据模型
3. 实现配置类CryptoProperties
4. 实现异常体系

### 8.2 第二阶段：核心组件

1. 实现EnvelopeCodec信封编解码器
2. 实现AeadCipher AEAD加密器
3. 实现KeyCache密钥缓存
4. 实现KmsClient接口和Feign实现
5. 实现DeviceResolver接口和默认实现

### 8.3 第三阶段：集成测试

1. 实现CryptoTemplate门面API
2. 实现CryptoAutoConfiguration自动配置
3. 实现CryptoMetrics可观测性
4. 集成测试和验证

## 9. 风险和注意事项

1. **安全性**：明文DEK和业务数据仅在内存中，不持久化
2. **性能**：合理设置缓存TTL和大小，避免频繁调用KMS
3. **容错**：严格遵循fail-closed原则，任何依赖不可用都拒绝服务
4. **兼容性**：确保信封头格式与车端SE实现对齐
5. **配置**：所有阈值均可通过Nacos动态调整
