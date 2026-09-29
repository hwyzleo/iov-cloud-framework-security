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
      profiles:
        TBOX_TSP_CLIENT:                    # 键 = framework 治理的 CertificateProfile.name
          provisioner: openiov              # step-ca provisioner
          kid: ${STEP_CA_OPENIOV_KID}       # provisioner JWK 的 kid
          max-validity: 365d                # 最大签发有效期（不得超 step-ca 模板上限）
          allowed-key-algorithms: [EC_P256]
          required-eku: [CLIENT_AUTH]
          subject-rule: TBOX                # subject/SAN 前缀约束（防越权）
```

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
