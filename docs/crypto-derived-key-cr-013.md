# 根派生与随机材料模型拆分（FW-SEC-DSN-CR-013）

本文档记录 `FW-SEC-DSN-CR-013` 在 `iov-cloud-framework-security` 的落地：
恢复「受治理 Transit 根 + 锚派生」主模型（`deriveAndWrap`），并将业务密钥材料按
`KeyMaterialModel` 显式分派，随机材料门面仅承接独立随机材料型。本 CR **取代** CR-011 中
「云侧统一 create/wrap 随机材料」的口径，为 `FW-SEC-DSN-CR-011` 的收窄变更。

> 变更对：需求 `FW-SEC-REQ-CR-013` / 设计 `FW-SEC-DSN-CR-013`。

## 1. 材料模型拆分

`BizType` 新增 `materialModel` 能力声明，作为受治理的**类型分类**（禁止依据方法调用动态猜测）：

| `KeyMaterialModel` | 语义 | 承接门面 | 首期取值 |
| --- | --- | --- | --- |
| `DERIVED_ROOT` | 根派生型：由 Transit/HSM 受治理根按规范化锚 + `KeyPurpose` + 派生版本确定性生成，并在受控边界内原子封装 | `KeyProvisioningTemplate.deriveAndWrap` | `V2C_COMM_ROOT`、`IMMO_GROUP_KEY`、`OTA_VEHICLE_ROOT`、各 `*_DEVICE_ROOT` |
| `RANDOM_MATERIAL` | 独立随机材料型：Provider 生成并密封保存，按显式 `keyRef` 管理 | `BusinessKeyMaterialTemplate` | **暂无（v1 无枚举项）** |
| `null` | 非对称签名条目，不属对称材料模型 | 两个门面均 fail-closed | `IDK_KTS_SIGNING` |

判定辅助：`BizType.supportsDerivedRoot()`（`prov != null && materialModel == DERIVED_ROOT`）、
`BizType.supportsRandomMaterial()`（`materialModel == RANDOM_MATERIAL`）。

**新增 `RANDOM_MATERIAL` 枚举项须走 CR + framework 发版**（当前无真实条目）。

## 2. 主入口 `deriveAndWrap`（Java API）

```java
DerivedWrappedKey deriveAndWrap(
        BizType bizType, KeyAnchor anchor, KeyPurpose purpose,
        RecipientRef recipient, DerivationContext context,
        String operationId, String idempotencyKey);
```

framework 侧编排（`DefaultKeyProvisioningTemplate`）：

1. **材料模型门禁**：`requireDerivedRoot(bizType)`，不满足抛 `KeyMaterialModelMismatchException`。
2. **锚层级校验**：`BizType.prov().anchor` 须与锚类型一致 —— `Anchor.VEHICLE` 要求 `KeyAnchor.AnchorType.VIN`，
   `Anchor.DEVICE` 要求 `UID`；否则抛 `CryptoException(INVALID_KEY_ANCHOR)`。
3. **证书证据解析**：`recipient` 为 `RecipientRef.DeviceCertificate` 时经 `CertResolver` 取受信证书
   DER/SPKI/SHA-256 指纹，并按 `CertificateEvidenceValidator` 校验；首期仅支持该收方，
   其它收方抛 `CryptoException(UNSUPPORTED_RECIPIENT)`。
4. **受治理根映射**：根引用 = `openbao-transit://transit/keys/{bizType.prov().keyName()}`；
   **客户端不发送 `rootKeyRef`**，Provider 侧按 `bizType` 策略表路由（`rootKeyRef` 仅作不透明引用/元数据）。
5. `operationId`/`idempotencyKey` 必填非空。

收方映射与随机材料门面一致：`KmsRecipient.deviceCertificate(serial, der, sha256Fingerprint, spki, null)`。

## 3. Provider wire 契约（`POST /v1/business-key/derived-keys:wrap`）

`KmsFeignClient.deriveAndWrap(DeriveAndWrapRequest) → DerivedWrapResponse`。

请求字段（**权威口径**）：

```json
{
  "bizType": "V2C_COMM_ROOT",
  "derivationVersion": "v1",
  "anchor": {
    "type": "VIN",
    "normalizationVersion": "vin-v1",
    "value": "<规范化 VIN 原文>",
    "digest": "sha256:<64-hex>"
  },
  "purpose": "UPLINK_AEAD",
  "recipient": {
    "mode": "DEVICE_CERT_PUBLIC_KEY",
    "certificateDer": "<base64>",
    "spki": "<base64>",
    "sha256Fingerprint": "<hex>"
  },
  "operationId": "<UUIDv7>",
  "idempotencyKey": "<...>"
}
```

响应字段：

```json
{
  "logicalKeyId": "...",
  "kmsKeyRef": "...",
  "rootKeyVersion": 3,
  "derivationVersion": "v1",
  "wrapped": "<base64>",
  "wrappingAlgorithm": "RSA-OAEP-SHA256",
  "kcv": "<hex>",
  "operationId": "<UUIDv7>"
}
```

- **锚原文与摘要**：`anchor.value` 为**规范化后的锚原文**（参与 HMAC 派生），
  `anchor.digest = "sha256:" + sha256Hex(value)` 仅用于完整性比对，**不参与派生**。
- **派生公式**（Provider 侧持有 `K_v2c_root`）：
  `HMAC-SHA256(K_v2c_root, UTF8("openiov|v2c|" + derivationVersion + "|" + normalizedVin + "|" + purpose))`。
  digest 不进入派生输入。
- **Provider 摘要校验**：Provider 重算 `digest` 与 `anchor.digest` 比对，不一致返回
  `422 ANCHOR_DIGEST_MISMATCH`（`KmsErrorCode.ANCHOR_DIGEST_MISMATCH`）。
- **KCV**：`first_3_bytes(SHA-256(keyMaterial))`，在 Provider 边界内计算，经 `kcv`（hex）返回；
  framework 侧 `decodeHex` 解码为 `byte[]`（非法 hex fail-closed）。
- **幂等**：`kmsKeyRef` 由 Provider 生成，消费者不得解析出锚原文；同锚/purpose/根版本/派生版本代表同一逻辑密钥，
  换收方证书只改变 Wrapped Key，不改变逻辑材料与 KCV。

### 3.1 异常分类（framework ↔ Provider）

复用 `FeignKmsClient.classify(...)`：

| Provider 响应 | framework 映射 |
| --- | --- |
| 409 `IDEMPOTENCY_CONFLICT` | `BusinessKeyIdempotencyConflictException` |
| 422（含 `ANCHOR_DIGEST_MISMATCH`） | `CryptoDependencyUnavailableException`（依赖不可用） |
| 404 非契约路由 | `CryptoDependencyUnavailableException` |
| 5xx / 超时 | `CryptoOperationOutcomeUnknownException`（携带 `operationId`，须以原 operationId/幂等键对账） |
| DNS/连接失败（请求体未发送） | `CryptoDependencyUnavailableException`（可按预算重试） |

### 3.2 §8 wire 勘误（仅在代码/文档落地）

设计文档 §8 的示例仅给出 `rootKeyRef` + `anchorDigest`，与权威口径不符。**以本文 §3 为准**：
客户端**不发送** `rootKeyRef`，锚完整性字段为 `anchor.digest`（随 `anchor` 对象一并上送）。
该勘误**不修改 Notion**，仅在代码与本文档记录。

## 4. 随机材料门面路由 fail-closed

`DefaultBusinessKeyMaterialTemplate.create()` 入口新增 `requireRandomMaterial(bizType)`：
仅 `RANDOM_MATERIAL` 可进本门面，`DERIVED_ROOT` 与 `null` 一律抛 `KeyMaterialModelMismatchException`，
**不回退随机材料**。`DERIVED_ROOT` 须走 `KeyProvisioningTemplate.deriveAndWrap`。

测试注入：v1 无 `RANDOM_MATERIAL` 枚举项（枚举不可 mock），通过受治理扩展点
`DefaultBusinessKeyMaterialTemplate.materialModelOf(BizType)`（生产实现恒取 `bizType.materialModel()`）
在测试子类中注入，以覆盖 create 正向路径。

## 5. legacy 门面废弃

`KeyProvisioningTemplate` 中原 `deriveByVin/deriveByUid/wrapByVin/wrapByUid/wrapFor` **保留签名并 `@Deprecated`**，
一律 fail-closed（`CryptoException(LEGACY_FACADE_UNSUPPORTED)`）：缺少派生所需的 purpose/operationId/幂等键，
**不提供隐式默认 purpose，也不生成随机幂等键**。

`unwrapByVin/unwrapByUid` **保留签名并 `@Deprecated`**，仅在受控 legacy 对称 KEK 场景下可用：

```yaml
crypto:
  provisioning:
    legacy-facade:
      enabled: false   # 默认 false；仅 legacy 对称 KEK 场景显式开启
```

开启后走旧 `decryptWith("dev-{sn|uid}")` 对称 KEK 路径；默认关闭时同样 fail-closed。

## 6. 安全边界

**只允许 `anchor.digest` 出现在**日志、指标、审计摘要、`kmsKeyRef` 与 operation 记录中。
**禁止**记录：VIN 原文、派生明文、完整 Wrapped Key、KCV 明文。`KeyAnchor.toString()` 与
`DerivedWrappedKey.toString()` 均已脱敏（仅输出字节长度）。

VIN 规范化：`trim → ASCII 大写 → 长度==17 → 字符集 [A-HJ-NPR-Z0-9]`（ISO 3779，排除 I/O/Q）；
不合法在 `KeyAnchor.vin(...)` fail-closed。规范化规则版本 `vin-v1`。

## 7. 配置示例

```yaml
crypto:
  kms:
    endpoint: http://openiov-openbao:8200
    provider: openbao-business-key
  provisioning:
    enabled: true                 # 装配 KeyProvisioningTemplate（deriveAndWrap）
    legacy-facade:
      enabled: false              # legacy 解封门面默认关闭
  business-key:
    enabled: true                 # 装配 BusinessKeyMaterialTemplate（仅 RANDOM_MATERIAL）
```

## 8. 迁移指引

- 旧 `deriveByVin/deriveByUid/wrapByVin/wrapByUid/wrapFor` 调用方 → 改用
  `deriveAndWrap(bizType, anchor, purpose, recipient, DerivationContext.v1(), operationId, idempotencyKey)`；
  显式提供 purpose、operationId 与幂等键。
- 车级业务用 `KeyAnchor.vin(vin)`；设备级业务用 `KeyAnchor.uid(uid)`。
- 派生结果（Wrapped Key）为**瞬时**值，使用后即释放，不落库、不进日志/事件。
- 写操作结果未知时以原 `operationId`/幂等键对账，**不换键重建**。

## 9. 测试覆盖

- 单元：`KeyAnchorTest`、`BizTypeMaterialModelTest`、`DefaultKeyProvisioningTemplateTest`、
  `DefaultBusinessKeyMaterialTemplateTest`、`client/FeignKmsClientDerivedKeyTest`。
- 集成：`DerivedKeyProvisioningContractIntegrationTest`（自动装配 + 真实 `FeignKmsClient` + mocked `KmsFeignClient`，
  贯通 deriveAndWrap 请求/响应映射、purpose 域隔离、422 fail-closed、`DERIVED_ROOT` 不进随机材料门面）、
  `BusinessKeyProviderContractIntegrationTest`（随机材料门面 create/wrap/metadata/revoke/reconcile）。
