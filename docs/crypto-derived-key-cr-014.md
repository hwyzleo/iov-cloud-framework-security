# V2C 派生封装完整信封、字节级幂等与受控结果存储（FW-SEC-DSN-CR-014）

本文档记录 `FW-SEC-DSN-CR-014` 在 `iov-cloud-framework-security` 的落地。
本 CR 在 `FW-SEC-DSN-CR-013`（受治理 Transit 根 + 锚派生主模型）之上，
把 EC 收方的「派生 + 封装」升级为**完整自描述版本化信封**（ECDH-ES P-256 +
HKDF-SHA-256 + AES-256-GCM），并给出**字节级幂等**、**受控 Provider 结果存储**与
**证书确定性拒绝分类**三项收窄/修订口径。

> 变更对：需求 `FW-SEC-REQ-CR-014` / 设计 `FW-SEC-DSN-CR-014`。

## 1. 封装套件（WrappingSuite）

新增受治理的封闭枚举 `WrappingSuite`（禁止业务传入任意字符串；新增取值走 CR + 发版）：

| 枚举 | 规范名 `spec` | Provider wire 名 | 收方公钥算法 | 语义 |
| --- | --- | --- | --- | --- |
| `ECDH_ES_P256_HKDF_SHA256_AES256GCM` | `ECDH-ES-P256/HKDF-SHA-256/AES-256-GCM` | `ECDH-ES+A256GCM` | `EC` | ECDH-ES（NIST P-256）+ HKDF-SHA-256 派生 32 字节 KEK + AES-256-GCM（96-bit nonce，128-bit tag）|
| `RSA_OAEP_SHA256` | `RSA-OAEP-SHA256` | `RSA-OAEP-SHA256` | `RSA` | RSA-OAEP（SHA-256）直接封装 |

- 套件**由 framework 依据收方证书证据的公钥算法推导**（`WrappingSuite.forRecipientKeyAlgorithm`，
  EC→ECDH-ES / RSA→RSA-OAEP），不由调用方指定；无法推导即 fail-closed。
- `WrappingSuite.fromWireName(...)` 解析 Provider 返回值，未知即 fail-closed。
- `isEcdh()` 标记需要 P-256 与 `keyAgreement` 的套件。

## 2. 主入口 `deriveAndWrap`（Java API）变更

签名不变（`FW-SEC-DSN-CR-013 §2`）：

```java
DerivedWrappedKey deriveAndWrap(
        BizType bizType, KeyAnchor anchor, KeyPurpose purpose,
        RecipientRef recipient, DerivationContext context,
        String operationId, String idempotencyKey);
```

`DefaultKeyProvisioningTemplate` 编排新增：

1. **套件推导**：解析收方证书 SPKI 公钥算法（`CertificateEvidenceValidator.publicKeyAlgorithm`），
   推导 `WrappingSuite`；不支持/无法解析密钥抛 `CertificateEvidenceRejectedException(UNSUPPORTED_RECIPIENT_KEY)`
   （不可重试），空 SPKI 抛 `CryptoDependencyUnavailableException`。
2. **幂等上下文**：`DerivationInput` 扩展为 7 字段，携带 `wrappingSuite`、`requestId`、
   `businessDomain`（=`bizType.name()`）与 `businessKeyVersion`；`requestId` 取自
   `RecipientRef.DeviceCertificate.requestId()`。
3. `DerivationContext` 扩展 `businessKeyVersion`（VMD 维护），与 `derivationVersion`（派生格式版本）、
   `rootKeyVersion`（根版本）三者分离，互不代替。

### 2.1 `DerivedWrappedKey` 重塑（§5.1，破坏性）

`DerivedWrappedKey` 由「裸 Wrapped Key + `wrappingAlgorithm` 字符串」重塑为**信封化**结果：

```java
record DerivedWrappedKey(
        String logicalKeyId,
        String kmsKeyRef,
        long rootKeyVersion,
        String derivationVersion,
        WrappingSuite wrappingSuite,     // 新增（必填，无隐式推断）
        byte[] envelopeBytes,            // 原 wrapped → canonical 信封 bytes（瞬时，转发用）
        byte[] envelopeDigest,           // 新增：SHA-256(canonicalEnvelopeBytesWithoutDigest)
        byte[] kcv,
        String operationId) { ... }
```

- 所有 `byte[]` 组件**防御性复制**（构造 + 访问器）；`wrappingSuite` 非空（`Objects.requireNonNull`）。
- `toString()` 脱敏：仅输出 `[N bytes]`，不回显信封/KCV 内容。
- 消费者（framework、VMD、VAGW、TSP）只处理 `envelopeBytes` 与非敏感元数据，
  **绝不接收根密钥或派生明文**；VMD 只读取元数据并转发 bytes，不得解析 ECDH 私密中间状态。

## 3. canonical 字节权威（§3.2/§3.3/§4）

跨端（Java Provider ↔ C++/TBOX-SEC ↔ HSM）**单一权威**定义在
`codec/DerivedKeyEnvelopeCanonical` + `codec/CanonicalEncoding`：

- **编码原语**：长度前缀 `int32 大端长度 || 原始字节`，字段顺序固定，字符串统一 UTF-8；
  禁止本地默认字符集、平台换行、未定义 JSON 序列化作为 KDF/AAD/摘要输入。
- `sha256(byte[])` / `hexLower(byte[])` / `constantTimeEquals(byte[], byte[])`（`MessageDigest.isEqual`）。

### 3.1 HKDF info（§3.2）

```
openiov|keyprov-wrap|v1|{requestId}|{businessDomain}|{purpose}
  |{keyId}|{businessKeyVersion}|{recipientCertificateFingerprintHexLower}
```

协议标签 `KDF_INFO_LABEL = openiov|keyprov-wrap|v1`。指纹统一**小写十六进制**
（`lowerHexOrEmpty`，`trim` 后小写），字段缺失按空串/声明值编码。

### 3.2 AAD 与 aadDigest（§3.3）

`EnvelopeAadV1` = `envelopeVersion, wrappingSuite, requestId, businessDomain, purpose,
keyId, businessKeyVersion, rootKeyVersion, derivationVersion, recipientCertificateFingerprint`。
`aadBytes(aad)` 按上序长度前缀编码；`aadDigest = SHA-256(aadBytes)`。

### 3.3 信封 canonical bytes 与 envelopeDigest（§4）

`DerivedWrappedKeyEnvelopeV1` = `envelopeVersion, wrappingSuite, serverEphemeralPublicKey,
hkdfSalt, hkdfContextVersion, nonce, ciphertext, authenticationTag, aad, aadDigest,
recipientCertificateFingerprint, logicalKeyId, purpose, businessKeyVersion, rootKeyVersion,
derivationVersion, kcv, operationId, envelopeDigest`。

- `envelopeBytesWithoutDigest(...)` 按上序长度前缀编码（**不含** `envelopeDigest`）；
  `envelopeDigest = SHA-256(envelopeBytesWithoutDigest)`。
- `verifyEnvelopeDigest` / `verifyAadDigest` 恒时比较校验；未携带摘要返回 false（fail-closed）。
- 信封**自描述**：canonical AAD 作为信封的 `aad` 字段随信封一并下发，
  TBOX SEC/HSM 仅凭信封即可重建 info、派生 KEK 并解封，**不依赖 VMD/VAGW 注入隐式参数**。
- `serverEphemeralPublicKey` 为 **65 字节 SEC1 未压缩点**（`0x04 || X || Y`）。

## 4. Provider wire 契约（`POST /v1/business-key/derived-keys:wrap`）

### 4.1 请求（`DeriveAndWrapRequest`）

在 CR-013 §3 请求基础上新增：

```json
{
  "bizType": "V2C_COMM_ROOT",
  "derivationVersion": "v1",
  "anchor": { "type": "VIN", "normalizationVersion": "vin-v1", "value": "<规范化 VIN>", "digest": "sha256:<64-hex>" },
  "purpose": "UPLINK_AEAD",
  "recipient": { "mode": "DEVICE_CERT_PUBLIC_KEY", "certificateDer": "<base64>", "spki": "<base64>", "sha256Fingerprint": "<hex>" },
  "wrappingSuite": "ECDH-ES+A256GCM",
  "requestDigest": "<64-hex>",
  "operationId": "<UUIDv7>",
  "idempotencyKey": "<...>"
}
```

### 4.2 响应（`DerivedWrapResponse` → `DerivedWrappedKey`）

新增完整信封字段（替换原 `wrapped` + `wrappingAlgorithm`）：

```json
{
  "logicalKeyId": "...",
  "kmsKeyRef": "...",
  "rootKeyVersion": 3,
  "derivationVersion": "v1",
  "purpose": "UPLINK_AEAD",
  "businessKeyVersion": 7,
  "wrappingSuite": "ECDH-ES+A256GCM",
  "envelopeVersion": "v1",
  "serverEphemeralPublicKey": "<base64 65-byte SEC1>",
  "hkdfSalt": "<base64 32-byte>",
  "hkdfContextVersion": "v1",
  "nonce": "<base64 12-byte>",
  "ciphertext": "<base64>",
  "authenticationTag": "<base64 16-byte>",
  "aad": "<base64 canonical AAD>",
  "aadDigest": "<hex|base64>",
  "recipientCertificateFingerprint": "<hex lower>",
  "envelopeBytes": "<base64；可选，若回传须与 canonical bytes 逐字节一致>",
  "envelopeDigest": "<hex|base64>",
  "kcv": "<hex>",
  "operationId": "<UUIDv7>"
}
```

`FeignKmsClient.mapDerivedWrappedKey` 映射顺序（任一失败即 fail-closed）：

1. `wrappingSuite` 未知 → `CryptoDependencyUnavailableException`；
2. `kcv` 十六进制非法 → fail-closed（复用 `decodeHex`）；
3. 组装 `DerivedWrappedKeyEnvelopeV1`；
4. `ciphertext` 缺失/空、`aad` 缺失 → `CryptoDependencyUnavailableException`；
5. 重算校验 `aadDigest`、`envelopeDigest`（恒时比较）；
6. framework 以 canonical 权威编码器**重建** `envelopeBytes`；Provider 若回传 bytes 须**逐字节一致**，
   否则 `CryptoDependencyUnavailableException`；
7. 输出 `DerivedWrappedKey`（`envelopeBytes` = framework canonical bytes）。

### 4.3 幂等请求摘要（§5.2）

`codec/DerivedKeyRequestDigest.requestDigest(...)`，协议标签 `openiov|keyprov-req|v1`，
长度前缀覆盖（固定顺序）：

```
caller + bizType + rootRef + requestedRootVersionPolicy
  + derivationVersion + normalizedAnchorDigest + purpose
  + requestId + businessKeyVersion + recipientCertificateFingerprint + wrappingSuite
```

- framework 侧组装受治理输入并计算 `requestDigest`（`caller`/`rootVersionPolicy`
  由 `crypto.provisioning.*` 配置提供，默认 `iov-framework-security` / `latest`）；
- 相同 `operationId` + 相同摘要 → 返回**字节级相同**信封；不同摘要 → Provider 返回
  `409 IDEMPOTENCY_CONFLICT` → `BusinessKeyIdempotencyConflictException`（不可重试）。

### 4.4 异常分类（§7.2）

| Provider 响应 | framework 映射 | 可重试 |
| --- | --- | --- |
| 409 `IDEMPOTENCY_CONFLICT` | `BusinessKeyIdempotencyConflictException` | **否** |
| 422（含 `ANCHOR_DIGEST_MISMATCH`） | `CryptoDependencyUnavailableException` | 是 |
| 404 非契约路由 | `CryptoDependencyUnavailableException` | 是 |
| 5xx / 超时 | `CryptoOperationOutcomeUnknownException`（携带 `operationId`） | 视情况（须对账）|
| DNS/连接失败 | `CryptoDependencyUnavailableException` | 是 |

`CryptoException` 新增 `isRetryable()`（默认 `true`），确定性失败覆写为 `false`。

## 5. 受控 Provider 结果存储（对 CR-013「绝不落库」的定向例外）

CR-013 规定派生信封「使用后即释放、不落库」。CR-014 明确一项**受控例外**：

- Provider（OpenBao 插件，**本仓库范围外**）在受控边界内持久化「operation 结果」
  以支撑**密码学幂等**（同 operationId + 同摘要重放返回原信封）与 TTL 回收；
- 该存储**仅**保存设备专属信封（已对收方公钥封装）与操作元数据，
  **不**保存根密钥、派生明文或 KEK；
- framework 侧不落库、不缓存 `DerivedWrappedKey`；framework 只通过
  capability `resultStoreReady` **门禁**该能力（§8）。

## 6. 证书确定性拒绝分类（§7.1/§7.2）

新增 `CertificateEvidenceRejectedException`（`Reason` 封闭集合 + `Action.DO_NOT_RETRY`，
`isRetryable()` 恒 `false`）与 `CryptoException.Reason.CERTIFICATE_EVIDENCE_REJECTED`。
`CertificateEvidenceValidator` 对**证书固有属性**的确定性失败统一抛本异常：

| 校验 | 触发 | Reason |
| --- | --- | --- |
| 公钥算法白名单 | 不在 `allowedKeyAlgorithms` | `KEY_ALGORITHM_NOT_ALLOWED` |
| 曲线（业务封装场景） | EC 收方非 NIST P-256 | `CURVE_NOT_ALLOWED` |
| 有效期 | 尚未生效 / 已过期 / 区间非法 | `CERTIFICATE_NOT_YET_VALID` / `CERTIFICATE_EXPIRED` / `CERTIFICATE_VALIDITY_INVALID` |
| KU | EC 缺 `keyAgreement`（bit 4）/ RSA 缺 `keyEncipherment`（bit 2）/ 不支持的公钥类型 | `KEY_USAGE_NOT_PERMITTED` / `UNSUPPORTED_RECIPIENT_KEY` |
| EKU | 缺必需 EKU 或无 EKU | `EXTENDED_KEY_USAGE_NOT_PERMITTED` |
| 受信链 | 无法验证到 `trust-anchors-pem` | `CHAIN_NOT_TRUSTED` |
| 吊销状态 | `REVOKED` | `CERTIFICATE_REVOKED` |

**语义边界**：

- `Scenario.BUSINESS_KEY_WRAP` 的 EC 收方强制 P-256（`isP256`：字段 256 位 + order/generator/cofactor 比对）。
- `digitalSignature` **不等价于** `keyAgreement`。
- `UNKNOWN` 吊销状态**不**归入拒绝：仍抛 `CertificateMaterialUnavailableException`（依赖不可用、**可重试**）；
  OCSP/CRL 暂时不可达同样按依赖不可用（可重试）。
- **不得**把策略拒绝包装为 `CertificateMaterialUnavailableException`。
- 校验顺序：声明一致性 → 公钥算法 → 有效期 → KU → 受信链 → GOOD 状态。

## 7. 导入证明（§8）

`codec/ImportProofCanonical` 提供 canonical 输入（**bound to `envelopeDigest` + `kcv`**）：

```
proofInput = lengthPrefixed(
  "openiov|keyprov-ack|v1" ... requestId ... businessDomain ... purpose
  ... keyIdDigest ... businessKeyVersion,
  envelopeDigest, kcv)
```

- TBOX SEC/HSM 使用实际导入密钥执行批准的 HMAC/CMAC，或使用批准的设备证明密钥签名，
  产生对上述输入的导入证明；`matches(...)` 恒时校验。
- framework 只提供 canonical builder 与验证工具，**不**持有业务密钥。
- KCV（`first_3_bytes(SHA-256(businessKey))`）仅用于材料一致性校验，
  **不替代** AEAD tag 或设备持钥证明。

## 8. 就绪门禁（§9）

`KmsProviderCapabilities` 新增 `derivedEnvelopeVersions` 与 `resultStoreReady`
（8 字段向后兼容构造默认无信封版本、`resultStoreReady=true`；`down()` 为 false）。
`KmsBusinessKeyProviderReadiness` 在既有门禁之上，**仅当 `crypto.provisioning.enabled=true`** 时追加
deriveAndWrap READY 门禁：

- `resultStoreReady == true`（否则 DOWN：幂等/TTL 不可用）；
- 支持信封版本 `v1`；
- 支持算法 `ECDH_P256`、`HKDF_SHA256`、`AES_256_GCM`。

任一不满足即 readiness DOWN（启动 fail-closed 或探针失败），不降级、不回退。

## 9. 安全边界

- **允许**出现在日志/指标/审计/`kmsKeyRef`/operation 记录：`envelopeDigest`、`aadDigest`、
  指纹（小写 hex）、版本元数据。
- **禁止**记录：根密钥、派生明文、KEK、ECDH shared secret、临时 EC 私钥、完整信封密文、KCV 明文。
  `DerivedWrappedKey.toString()` 与 `DerivedWrappedKeyEnvelopeV1.toString()` 均已脱敏。
- 受控结果存储（§5）只存已封装信封与操作元数据，不得含明文密钥材料。

## 10. 配置示例

```yaml
crypto:
  kms:
    endpoint: http://openiov-openbao:8200
    provider: openbao-business-key
  provisioning:
    enabled: true
    caller: iov-framework-security   # 参与 Provider 幂等请求摘要（§5.2）
    root-version-policy: latest      # 参与 Provider 幂等请求摘要（§5.2）
```

## 11. 迁移指引

- `DerivedWrappedKey` 消费者：改用 `envelopeBytes()`（完整自描述信封）替代原 `wrapped()`；
  套件信息由 `wrappingSuite()` 读取，不再解析 `wrappingAlgorithm` 字符串。
- `DerivationContext` 调用方：如需参与幂等域隔离，使用 `DerivationContext.of(version, businessKeyVersion)`；
  单参构造等价于 `businessKeyVersion=0`。
- 设备端：仅凭信封（含 canonical `aad`）独立重建 info 并解封，不得依赖外部注入密码参数。
- 写操作结果未知时以原 `operationId`/幂等键对账，**不换键重建**；同摘要重放须返回字节级相同信封。
- 证书策略拒绝（§6）应映射为非可重试业务错误，**不得**自动重试或换证重试。

## 12. 测试覆盖

- **跨端 canonical 向量**：`codec/DerivedKeyCanonicalVectorTest` —— 以独立实现（长度前缀 + UTF-8 + SHA-256）
  计算并冻结 `kdfInfo`/`aadBytes`/`aadDigest`/`envelopeBytesWithoutDigest`/`envelopeDigest`/`requestDigest`/`proofInput`
  的字节级向量（`aadDigest=10981bfb…aace`、`envelopeDigest=71ebe7d7…c933`、
  `requestDigest=dbdb26dd…b543`），并覆盖恒时比较与字段变更敏感性。
- **模型**：`model/DerivedKeyEnvelopeModelTest` —— 防御性复制、脱敏 `toString`、`wrappingSuite` 非空。
- **参考解封器**（测试范围 Java 参照实现 ECDH+HKDF+AES-GCM）：`support/ReferenceDerivedKeyUnwrapperTest` ——
  端到端往返、purpose 域隔离、证书轮换（KCV 稳定 / 摘要变化）、逐字段篡改失败、压缩点拒绝。
- **client**：`client/FeignKmsClientDerivedKeyTest` —— 请求/响应映射、未知套件与 `aadDigest`/`envelopeDigest`
  篡改及 Provider bytes 偏离 fail-closed、同 operation 重放字节级相同、409 不可重试；
  `client/KmsBusinessKeyProviderReadinessDerivedKeyTest` —— 派生门禁开/关、
  `resultStoreReady=false` / 信封版本缺失 / 算法缺失 → DOWN；
  `client/FeignKmsClientBusinessKeyTest` —— capabilities 派生字段映射。
- **证书校验**：`resolver/CertificateEvidenceValidatorTest` —— 过期/EKU/吊销/链不可信 →
  `CertificateEvidenceRejectedException`（含 reason、不可重试）；UNKNOWN 仍为
  `CertificateMaterialUnavailableException`（可重试）；EC 缺 `keyAgreement`、非 P-256 曲线拒绝。
- **集成**：`DerivedKeyProvisioningContractIntegrationTest` —— 自动装配 + 真实 `FeignKmsClient` + mocked `KmsFeignClient`
  贯通：端到端映射、往返解封、重放字节级相同、不同摘要 409 不可重试、敏感信息不入 `toString`、
  UPLINK/DOWNLINK 域隔离、`ANCHOR_DIGEST_MISMATCH` 422 fail-closed；
  `CertificateResolutionIntegrationTest` —— 吊销状态 fail-closed（不可重试）。

全量：`mvn -o test` → **Tests run: 518, Failures: 0, Errors: 0, Skipped: 0**（BUILD SUCCESS）。

## 13. 范围外（他仓 / 他组件负责）

- Provider/HSM 侧密码学实现：ECDH（P-256）、HKDF-SHA-256、AES-256-GCM、临时密钥生成；
- 受控结果存储的实际持久化 / TTL / 对账（OpenBao 插件）；
- TBOX SEC/HSM 侧独立解封与导入证明（HMAC/CMAC/签名）；
- PAR-PROTO wire 映射（后续 CR，但**不得改变本文 canonical bytes**）。

本仓库交付：类型与 canonical 契约（§1/§3）、编排与 fail-closed 门禁（§2/§4/§8）、
错误分类（§4.4/§6）、canonical builder/校验工具（§7）与上述单元/集成测试。
