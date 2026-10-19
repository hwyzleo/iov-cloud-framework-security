# 派生封装结构化信封视图与消费者契约（FW-SEC-DSN-CR-015）

本文档记录 `FW-SEC-DSN-CR-015` 在 `iov-cloud-framework-security` 的落地。
本 CR 在 `FW-SEC-DSN-CR-014`（完整自描述信封 + 字节级幂等）之上，把
`DerivedWrappedKey` 的私有 canonical `envelopeBytes` **消费者契约**收窄为
**结构化、只读、版本化**的 `DerivedWrappedKeyEnvelopeView`：业务消费者（VMD/VAGW/TSP）
SHALL 通过视图读取 ciphertext / ECDH 参数 / digest / KCV，**禁止**解析私有 18-segment bytes。

> 变更对：需求 `FW-SEC-REQ-CR-015` / 设计 `FW-SEC-DSN-CR-015`（§4–§9）。
> 关联：`FW-SEC-DSN-CR-014`（canonical 权威）、`PAR-PROTO-DSN-CR-007`（VMD wire，本仓范围外）。

## 1. 决议锚点（本仓实现口径）

| 决议 | 结论 |
| --- | --- |
| digest 权威 | CR-014 canonical `envelopeDigest = SHA-256(canonicalEnvelopeBytesWithoutDigest)` 为**唯一权威**；core 侧不重定义 framing |
| PAR-PROTO 映射 | FW→PAR-PROTO bridge 属 **VMD 协议 Adapter**，`framework-security-keyprov-par-par-proto` 非公开 artifact；**本仓不实现、不声明** |
| `DerivedWrappedKey` 演进 | 新增 `envelope` 组件 + 保留旧 9 参构造函数 JVM descriptor（**兼容**而非破坏）；`envelope == null` 仅表示旧格式结果 |
| 一致性 | 顶层 `wrappingSuite`/`rootKeyVersion`/`derivationVersion`/`operationId`/`envelopeDigest`/`kcv` 与视图不一致即构造失败 |
| bindings | FW 结构化视图直接承载 CR-014 canonical `envelopeDigest`；PAR-PROTO `envelope_digest` 无损承载，不重新 framing；VMD/ACK/import proof/Provider 对账共用同一 digest |

## 2. 结构化视图类型（§4.1）

### 2.1 接口 `DerivedWrappedKeyEnvelopeView`（sealed）

只暴露 5 个跨模块稳定方法，首期唯一实现为 `EcdhEsP256EnvelopeViewV1`（新增信封格式走 CR + 发版并扩展 `permits`）：

```java
public sealed interface DerivedWrappedKeyEnvelopeView permits EcdhEsP256EnvelopeViewV1 {
    String envelopeFormat();          // ECDH_ES_P256_V1
    int formatVersion();              // 1
    WrappingSuite wrappingSuite();    // 必须与 DerivedWrappedKey 顶层一致
    byte[] envelopeDigest();          // 32 bytes，CR-014 canonical 摘要副本
    byte[] keyCheckValue();           // 3 bytes，first_3_bytes(SHA-256(businessKey)) 副本
}
```

- 所有 `byte[]` 访问器返回**防御性副本**，视图不可被外部改写；
- 视图**不含**临时私钥、ECDH shared secret、KEK、业务密钥明文。

### 2.2 实现 `EcdhEsP256EnvelopeViewV1`（record）

对 FW 私有 canonical 信封（`DerivedWrappedKeyEnvelopeV1`）的**只读结构化投影**，
字段与长度约束（构造即 fail-closed）：

| 字段 | 约束 |
| --- | --- |
| `formatVersion` | 必须 `== 1` |
| `wrappingSuite` | 必须 ECDH-ES（非 ECDH-ES 拒绝） |
| `serverEphemeralPublicKey` | 65 字节，SEC1 未压缩点（首字节 `0x04`） |
| `hkdfSalt` | 32 字节 |
| `nonce` | 12 字节 |
| `authenticationTag` | 16 字节 |
| `ciphertext` | 非空（`wrapped_key`） |
| `canonicalAad` | 非空且 ≤ 1024 字节（1 KiB） |
| `aadDigest` / `recipientCertificateDigest` / `envelopeDigest` | 各 32 字节 |
| `keyCheckValue` | 3 字节 |
| `businessKeyVersion` | `1 .. 2^63-1` |
| `rootKeyVersion` | `≥ 0` |
| `hkdfContextVersion` / `logicalKeyId` / `purpose` / `derivationVersion` / `operationId` | 非空 |

- `toString()` 脱敏：只输出格式/套件/版本与各 `byte[]` 的 `[N bytes]`，不展开密文；
- `equals`/`hashCode` 按字节内容比较。

### 2.3 工厂 `codec/DerivedEnvelopeViewFactory`

canonical 信封 → 结构化视图的**唯一受治理入口**（只做投影，不参与任何密码学计算，
不修改 ciphertext / canonical AAD / digest；CR-015 RD-015-3/RD-015-4）：

- `toEcdhEsP256View(envelope)`：非 ECDH-ES 套件、非法指纹、非法长度 → `IllegalArgumentException`；
- `recipientCertificateDigest(envelope)`：把信封的小写十六进制证书指纹还原为 **32 字节** SHA-256 证书摘要
  （复用 `CanonicalEncoding.hexDecode`，缺失/非 32 字节 fail-closed）。

`CanonicalEncoding` 新增 `hexDecode(String)`（容忍 `0x` 前缀与大小写；`null → null`；
奇数长度/非十六进制 → `IllegalArgumentException`）。

## 3. `DerivedWrappedKey` 增量演进（§4.2/§8）

新增 `envelope` 组件（10 字段 record），并保留旧 9 参构造函数：

```java
record DerivedWrappedKey(
        String logicalKeyId, String kmsKeyRef, long rootKeyVersion, String derivationVersion,
        WrappingSuite wrappingSuite,
        DerivedWrappedKeyEnvelopeView envelope,   // 新增（CR-015）
        byte[] envelopeBytes,                      // opaque，仅审计/结果存储兼容
        byte[] envelopeDigest, byte[] kcv, String operationId) { ... }
```

- **兼容**：`DerivedWrappedKey(9 args)` 保留（委托新构造，`envelope = null`），
  JVM descriptor 不变，既有消费者二进制与源码兼容；`DerivedWrappedKeyEnvelopeViewCompatibilityTest`
  以反射断言该 9 参构造函数存在（fail if 被移除）；
- **一致性校验**（`requireEnvelopeConsistent`，`envelope != null` 时）：
  `wrappingSuite`、`envelopeDigest`、`kcv` 必须与顶层相等；
  `EcdhEsP256EnvelopeViewV1` 额外校验 `rootKeyVersion`/`derivationVersion`/`operationId`/`logicalKeyId`；
  任一不一致 → `IllegalArgumentException`；
- **语义**：`envelope == null` **仅**表示旧格式结果（不是 ECDH-ES v1 已就绪）；
  声明 `STRUCTURED_ENVELOPE_VIEW_V1` 后，ECDH-ES v1 成功结果**不允许** `envelope == null`；
- `equals`/`hashCode` 纳入 `envelope`；`toString()` 只输出 `envelopeFormat/vN`，不回显 bytes。

## 4. 客户端映射与门禁（§7/§8）

`FeignKmsClient.mapDerivedWrappedKey` 在 CR-014 映射顺序之上追加一步：

1. `wrappingSuite` 未知 → `CryptoDependencyUnavailableException`；
2. `kcv` 十六进制非法 → fail-closed；
3. 组装 `DerivedWrappedKeyEnvelopeV1`；
4. `ciphertext`/`aad` 缺失 → fail-closed；
5. 重算校验 `aadDigest`、`envelopeDigest`（恒时比较）；
6. framework canonical 编码器**重建** `envelopeBytes`，Provider 回传 bytes 须逐字节一致；
7. **ECDH-ES v1 由 canonical 信封构建结构化视图**（`structuredEnvelopeView`）：构建失败即
   fail-closed（**禁止**回退解析私有 `envelopeBytes`）；非 ECDH-ES 返回 `envelope = null`；
8. 输出 `DerivedWrappedKey`。

## 5. 能力声明（§7）

`crypto/DerivedEnvelopeCapability` 声明本 artifact 支持的能力集合：

| 常量 | 本 artifact 支持 | 说明 |
| --- | --- | --- |
| `STRUCTURED_ENVELOPE_VIEW_V1` | **是** | core 结构化视图 |
| `PAR_PROTO_WIRE_MAPPER_V1` | 否 | VMD 协议 Adapter 职责 |
| `DETERMINISTIC_PARAMETERS_V1` | 否 | PAR-PROTO 侧 |
| `WIRE_DIGEST_SELF_CHECK_V1` | 否 | PAR-PROTO Adapter 侧 wire 自校验 |

`supported()` 返回不可变集合（仅 `STRUCTURED_ENVELOPE_VIEW_V1`）。bridge artifact 缺失时，
新的 envelope v1 wire 下发 capability 保持 DOWN，**禁止**回退到私有 `envelopeBytes` 解析或空 parameters。

## 6. 安全边界

- **允许**出现在日志/指标/审计：`envelopeDigest`、`aadDigest`、收方证书摘要、版本元数据；
- **禁止**记录：根密钥、派生明文、KEK、ECDH shared secret、临时 EC 私钥、完整密文、KCV 明文；
  `DerivedWrappedKey`、`DerivedWrappedKeyEnvelopeV1`、`EcdhEsP256EnvelopeViewV1` 的 `toString()` 均已脱敏；
- 视图只做投影，不改变 CR-014 canonical 字节与 `envelopeDigest`（golden vector 不变）。

## 7. 跨端 digest 一致性（不重定义 framing）

- CR-014 canonical `envelopeDigest` 是唯一权威，**golden vector `71ebe7d7…c933` 不变**；
- 视图的 `envelopeDigest()` 直接承载该 canonical 摘要；PAR-PROTO 侧只无损承载到 `envelope_digest`，
  **不**新定义 framing digest；
- VMD / ACK / import proof / Provider 对账共用同一 digest；deterministic Protobuf serialization
  另由 golden vector 单独验证（PAR-PROTO 侧，本仓范围外）。

## 8. 迁移指引

- `DerivedWrappedKey` 消费者：优先读 `envelope()`（结构化视图），继续读取 `logicalKeyId`/`kmsKeyRef`/
  `rootKeyVersion`/`derivationVersion`/`wrappingSuite`/`operationId` 元数据；**停止**解析 `envelopeBytes`；
- 需要 ciphertext / ECDH 参数时：`((EcdhEsP256EnvelopeViewV1) key.envelope())` 读取
  `ciphertext()`/`serverEphemeralPublicKey()`/`hkdfSalt()`/`nonce()`/`authenticationTag()`/`canonicalAad()`；
- 旧代码可继续使用 9 参构造（得到 `envelope = null` 的旧格式结果），但新生成结果应带视图；
- `envelope == null` **不得**被当作 ECDH-ES v1 可用信号。

## 9. 测试覆盖

- **模型**：`model/EcdhEsP256EnvelopeViewModelTest`（8）—— 防御性复制、固定长度/点前缀/
  业务版本范围/非 ECDH-ES/非 v1 fail-closed、脱敏 `toString`、字节内容 `equals`。
- **兼容与一致性**：`model/DerivedWrappedKeyEnvelopeViewCompatibilityTest`（9）——
  旧 9 参构造函数 JVM descriptor 保留（反射断言）、`envelope == null` 旧格式语义、
  顶层/视图一致接受、suite/digest/kcv/元数据分歧 fail-closed、`equals`/`toString` 脱敏。
- **工厂**：`codec/DerivedEnvelopeViewFactoryTest`（7）—— 字段无损投影、证书指纹还原 32 字节摘要、
  投影确定性、非 ECDH-ES/非法指纹/null fail-closed、`hexDecode` 前缀与大小写。
- **能力**：`DerivedEnvelopeCapabilityTest`（3）—— 只声明 `STRUCTURED_ENVELOPE_VIEW_V1`，
  PAR-PROTO 三项恒不支持，不可变集合。
- **client**：`client/FeignKmsClientDerivedKeyTest`（16）—— 在原覆盖之上新增
  ECDH-ES v1 成功结果投影结构化视图（顶层/视图一致），以及 `businessKeyVersion=0` 视图构建 fail-closed。
- **集成**：`DerivedKeyProvisioningContractIntegrationTest` —— 端到端映射结果 `envelope != null`、
  视图字段与 canonical 信封逐字段一致、证书摘要还原、往返解封、字节级重放一致。

全量：`mvn -o test` → **Tests run: 547, Failures: 0, Errors: 0, Skipped: 0**（BUILD SUCCESS）。

## 10. 范围外（他仓 / 他组件负责）

- FW→PAR-PROTO wire bridge（`wrapped_key` ciphertext + deterministic parameters 映射、
  Protobuf golden vector、wire digest 自校验）：VMD 协议 Adapter / 可选 integration artifact；
- 受控结果存储 / TTL / 对账（OpenBao 插件）；
- TBOX SEC/HSM 侧独立解封与导入证明。

本仓库交付：结构化视图类型与工厂（§2）、`DerivedWrappedKey` 兼容演进与一致性校验（§3）、
客户端投影与 fail-closed（§4）、能力声明（§5）与上述单元/集成测试。
