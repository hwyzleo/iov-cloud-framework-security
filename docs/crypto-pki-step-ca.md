# step-ca 原生适配接入说明（FW-SEC-DSN-CR-008）

本文档说明如何将 `framework-security-starter` 的证书注册门面从自研 legacy-rest 切换为
smallstep step-ca 原生同步签发（HTTPS `POST /1.0/sign`）。公共门面 API
（`CertEnrollmentTemplate.apply/getStatus/getCertificate`）保持不变。

## 1. 配置示例

```yaml
crypto:
  pki:
    endpoint: https://step-ca:9000          # 必须 HTTPS；主机名须命中根证书 SAN（step ca init --dns）
    provider: step-ca                       # legacy-rest | step-ca；未配置时保持 legacy-rest
    enrollment:
      enabled: true                         # 证书注册门面装配开关（默认 true，仍需 endpoint）
    retry:
      max-attempts: 2                       # 仅对「请求尚未发送」（DNS/连接/TLS 握手）重试
      base-backoff: 100ms
    step-ca:
      root-sha256: ${STEP_CA_ROOT_SHA256}   # 根证书 SHA-256 指纹（信任锚，必填）
      token-provider: jwk                   # 当前仅支持 jwk
      token-ttl: 5m                         # OTT 有效期，默认 5 分钟且可缩短
      store-ttl: 30d                        # 结果存储 TTL，不短于业务补偿窗口
      jwk:
        private-key-file: /run/secrets/openiov-provisioner.jwk   # 只读 Secret（明文 JWK 或含 encryptedKey 的 step-ca JWK）
        password-file: /run/secrets/openiov-provisioner-password # 仅加密 JWK 需要，独立 Secret
        # 命名 signer（FW-SEC-DSN-CR-018）：多 Provisioner 路由。map key 为稳定非敏感 signerRef，
        # 保留名 __legacy__ 不可用作 key；file/content 二选一，password/password-file 二选一。
        signers:
          tsp-client:
            provisioner: openiov
            kid: ${STEP_CA_OPENIOV_KID}
            private-key-file: /run/secrets/openiov-provisioner.jwk
            password-file: /run/secrets/openiov-provisioner-password
      profiles:
        TBOX_TSP_CLIENT:                    # 键 = framework 治理的 CertificateProfile.name
          provisioner: openiov              # step-ca provisioner
          kid: ${STEP_CA_OPENIOV_KID}       # provisioner JWK 的 kid
          jwk-signer-ref: tsp-client        # 命名 signer 引用（FW-SEC-DSN-CR-018；未声明时走 legacy）
          max-validity: 365d                # 最大签发有效期（不得超 step-ca 模板上限）
          allowed-key-algorithms: [EC_P256]
          required-eku: [CLIENT_AUTH]
          subject-rule: TBOX                # subject/SAN 前缀约束（防越权）
```

### 多 JWK signer 路由（FW-SEC-DSN-CR-018）

- **两级路由**：逻辑 Profile → `StepCaProfilePolicy` 授权 → 选中唯一命名 signer（`jwk-signer-ref`）→
  用该 signer 私钥签发 OTT。调用请求不能直接选择 signer；`signerRef` 只由内部路由产生，不进入业务 API。
- **legacy 兼容**：未声明 `jwk-signer-ref` 的 Profile 自动回退到保留引用 `__legacy__`（使用
  `crypto.pki.step-ca.jwk` 顶层 legacy 单 JWK）；legacy 不存在时启动失败。`__legacy__` 是内部保留名，
  不得用作 signers map key。
- **路由一致性**：Profile 显式引用 signer 时，Profile 与 signer 的 `provisioner`/`kid` 必须一致，
  冲突不得以任一方覆盖（启动 fail-closed，禁止静默降级）。
- **配置校验（启动期 fail-closed）**：signerRef 格式/唯一性/保留名；每个启用 Profile 必须解析到唯一 signer；
  私钥/口令来源不冲突（file/content、password/password-file 各二选一）；JWK 必须是可签名私钥；
  配置 kid 与 JWK 自身 kid 一致；未使用 signer 告警但不被自动选中。
- **多 Provisioner 示例**（TSP 与 TBOX 设备 ECDH 各自独立 key/kid）：
  `signers.tsp-client`（provisioner=openiov）与 `signers.tbox-device-ecdh-v1`（provisioner=tbox-device-ecdh-v1）
  各自持钥；对应 Profile 分别引用；签名时 `JWS header.kid = 有效路由 kid`。

> **迁移**：阶段 A 零改动升级（legacy + 现有 Profile 不变，全走 `__legacy__`）；阶段 B 把存量 TSP JWK
> 移入 `signers.tsp-client` 并给存量 Profile 增 `jwk-signer-ref`（灰度期 legacy 与显式 signer 内容必须一致）；
> 阶段 C 登记 ECDH signer 并让新 Profile 引用（需 PKI 侧建好对应 Provisioner/独立 JWK/模板）；
> 阶段 D 待全部 Profile 有显式 signerRef 后清理 legacy 字段（另立兼容清理 CR，本 CR 不删除 legacy 支持）。

- `root-sha256` 获取：`step certificate fingerprint <root_ca.crt>`（大小写不敏感，可含/不含冒号）。
- JWK 私钥**严禁**写入 `application.yml` / Nacos；只允许只读 Secret 文件挂载（明文 JWK 或 step-ca 发布的
  口令加密 JWK）。若使用 step-ca 发布的 `encryptedKey`（ca.json 内嵌），解密口令必须独立 Secret 注入；
  生产优先配置客户端自持 JWK 或 KMS/HSM signer。

## 2. 信任与安全模型

- 启动时以配置根指纹调用 `GET {endpoint}/root/{sha256}` 并校验响应证书指纹（与官方 `step ca bootstrap`
  同款：根证书下载使用作用域受限的直信，随后对下载到的根做指纹固定；MITM 无法伪造与配置指纹一致的根）。
- 所有签发流量仅信任该校验后的根证书（受控 truststore，**禁止 trust-all**）。
- `POST /1.0/sign` 使用一次性 OTT（JWT）：`aud`=精确 sign URL、`sub`=证书主体、`sha`=根指纹、
  `sans`=允许 SAN、`jti`=requestId+nonce（一次性，禁止缓存复用），默认 ES256，TTL 默认 5 分钟。
- 签发响应校验：CSR 自签名、leaf 公钥=CSR 公钥、证书链签名、基本约束、有效期、profile EKU/KU、
  SAN/Subject 不越权、根指纹固定；校验失败不落成功结果。

## 3. 结果存储与幂等/重试语义

- 结果存储（Redis 优先、进程内仅 dev/test）适配 step-ca 无 requestId/status 三段式契约的语义：
  framework 生成 UUIDv7 requestId，`SUBMITTING → ISSUED/REJECTED/FAILED/UNKNOWN` 原子落库。
- 幂等/重试语义：
  - **FAILED / REJECTED（终态，未产生证书）→ 允许以同 idempotencyKey 重签**（失败可重试）；重签使用新
    requestId 覆盖幂等索引，旧终态记录保留供审计；
  - **UNKNOWN（请求已发送但结果未知）→ 禁止自动重签**，同 idempotencyKey 再次调用返回 UNKNOWN，
    由运维核对 CA 审计/数据库后受控恢复；
    **业务侧必须单独捕获 `PkiOutcomeUnknownException` 并映射为「结果未知/待对账」（如 PENDING_RECONCILE），
    不得落入通用 catch 误记为 FAILED**（FAILED 可重试、UNKNOWN 不可自动重签，语义不同）；
  - **ISSUED / 进行中（SUBMITTING/PENDING/APPROVING/PROCESSING）→ 幂等返回既有结果，不重复提交/签发**；
  - 同 key 但 CSR 或 profile 不同 → 抛幂等冲突异常。
- 仅 DNS/连接建立/TLS 握手失败（确认请求未发送）才按 `crypto.pki.retry` 预算重试。

## 4. 发布与回滚（FW-SEC-DSN-CR-008 §10）

1. 先发 framework 版本，默认仍为 legacy-rest（不配置 `provider` 即为存量行为）。
2. 在 VMD 环境准备：持久化结果存储（Redis）、step-ca 根指纹、openiov JWK Secret、`--dns` 命中 endpoint 主机名的根证书。
3. 将 `crypto.pki.provider` 切为 `step-ca`，`endpoint` 改为网络内可达 HTTPS 地址，移除占位 Bearer token。
4. 以测试 VIN/TBOX 完成申请、重复申请、重启恢复与错误注入后再放量。
5. 回滚仅切回 `legacy-rest`；已签发证书及 enrollment 记录不得删除。

## 5. 指标

- `crypto.enrollment.submit.count{provider=step-ca|legacy-rest}`
- `crypto.enrollment.outcome.count{provider, outcome=issued|rejected|failed|unknown|pending}`
- 标签仅固定枚举，禁止带 endpoint/subject/serial 等高基数字段。
