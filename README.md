# CleanC License Server

Cloudflare Workers + D1 + Turnstile 的 CleanC 授权服务。包含管理员后台、授权码、设备绑定、License Lease、动态主域名、Bootstrap 自动发现、操作日志与基础安全策略。

## 当前实现

- `/admin` Apple-inspired Liquid Glass 管理后台
- 管理员密码 + Cloudflare Turnstile 登录
- HttpOnly / Secure / SameSite=Strict Session
- CSRF 防护
- D1 登录限流与授权激活限流
- 单个授权码、随机批量授权码（最多 1000）
- 自定义授权码
- 永久 / 激活后 N 天 / 固定到期授权
- 设备数量限制
- 授权禁用 / 恢复
- 设备绑定 / 解绑
- 操作日志
- `POST /api/v1/license/activate`
- `POST /api/v1/license/validate`
- `POST /api/v1/license/refresh`
- `POST /api/v1/device/challenge`
- `POST /api/v1/device/verify`
- `GET /bootstrap/v1/config`
- `GET /api/v1/health`
- `GET /api/v1/meta`
- Bootstrap 与 License Lease 使用 P-256 / ECDSA SHA-256 数字签名
- `PRIMARY_BASE_URL` 保存到 D1，不在源码中写死正式域名
- 域名变更历史与审计
- GitHub Actions 自动执行 TypeScript 检查、D1 Migration 和 Worker 部署

## 重要安全原则

以下内容绝对不要提交到 GitHub：

- 管理员真实密码
- `SESSION_SECRET`
- Turnstile Secret Key
- License Signing Private Key
- Cloudflare API Token

实际管理员密码只写入 Cloudflare Secret `ADMIN_PASSWORD`。

## 第一次部署

### 1. 安装依赖

```bash
npm install
```

### 2. 登录 Cloudflare

```bash
npx wrangler login
```

### 3. 创建 D1

```bash
npm run d1:create
```

Cloudflare 会返回 D1 的 `database_id`。

把它写进 `wrangler.jsonc`：

```jsonc
"database_id": "你的真实 D1 database_id"
```

不要改 binding 名称，必须保持：

```text
DB
```

### 4. 创建 Turnstile

Cloudflare Dashboard → Turnstile → Add Widget。

把 Site Key 写到 `wrangler.jsonc`：

```jsonc
"TURNSTILE_SITE_KEY": "你的 Site Key"
```

Turnstile Secret Key 不写入仓库，后面通过 `wrangler secret put TURNSTILE_SECRET` 保存。

### 5. 生成服务器签名密钥

Worker 当前要求：

- ECDSA
- P-256
- SHA-256
- 私钥格式：PKCS#8 PEM
- 公钥格式：SubjectPublicKeyInfo PEM，供 CleanC 客户端验证

使用 OpenSSL：

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ec-private-sec1.pem
openssl pkcs8 -topk8 -nocrypt -in ec-private-sec1.pem -out cleanc-private.pem
openssl pkey -in cleanc-private.pem -pubout -out cleanc-public.pem
```

生成：

```text
cleanc-private.pem
cleanc-public.pem
```

`cleanc-private.pem` 只保存到 Cloudflare Secret：

```bash
npx wrangler secret put LICENSE_SIGNING_PRIVATE_KEY
```

执行命令后，把 `cleanc-private.pem` 的完整内容粘贴进去。

`cleanc-public.pem` 放进 CleanC Windows 客户端，用于验证：

- Bootstrap 响应
- License Lease

### 6. 配置 Worker Secrets

依次执行：

```bash
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put SESSION_SECRET
npx wrangler secret put TURNSTILE_SECRET
npx wrangler secret put LICENSE_SIGNING_PRIVATE_KEY
```

`SESSION_SECRET` 建议使用至少 32 字节随机值，例如：

```bash
openssl rand -base64 48
```

### 7. 初始化远程数据库

```bash
npm run db:remote
```

### 8. 部署 Worker

```bash
npm run deploy
```

部署成功后 Cloudflare 会给出类似：

```text
https://cleanc-license-server.<你的 workers.dev 子域>.workers.dev
```

管理员后台：

```text
https://cleanc-license-server.<你的 workers.dev 子域>.workers.dev/admin
```

健康检查：

```text
https://cleanc-license-server.<你的 workers.dev 子域>.workers.dev/api/v1/health
```

Bootstrap：

```text
https://cleanc-license-server.<你的 workers.dev 子域>.workers.dev/bootstrap/v1/config
```

## GitHub Actions 自动部署

仓库已经包含：

```text
.github/workflows/deploy.yml
```

在 GitHub：

```text
Settings
→ Secrets and variables
→ Actions
```

添加：

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

注意：GitHub Actions 部署前，必须先完成：

1. 创建 D1。
2. 把真实 D1 `database_id` 写入 `wrangler.jsonc`。
3. 创建 Turnstile，并写入 Site Key。
4. 给 Worker 配置四个 Cloudflare Secrets。

Worker 的管理员密码、Session Secret、Turnstile Secret、签名私钥无需保存到 GitHub Actions Secrets。

## 动态域名机制

系统区分三个概念：

```text
Bootstrap URL
Current Origin
Canonical Base URL
```

### 没有自定义域名时

`PRIMARY_BASE_URL` 不存在，系统自动使用当前 `workers.dev` Origin。

### 有自定义域名后

先在 Cloudflare：

```text
Workers & Pages
→ cleanc-license-server
→ Settings
→ Domains & Routes
→ Add Custom Domain
```

例如：

```text
license.example.com
```

然后在 Turnstile Hostname Management 添加同一个域名。

接着用新域名打开：

```text
https://license.example.com/admin
```

进入：

```text
设置
→ 域名与 API
```

输入管理员密码并完成第二次 Turnstile 验证后保存。

D1 会保存：

```text
PRIMARY_BASE_URL=https://license.example.com
```

之后：

- Bootstrap 返回新地址
- 后台 API 信息使用新地址
- CleanC 客户端可自动切换
- 无需重新编译 Worker
- 无需重新生成授权码

## 客户端永久保存什么

CleanC 客户端建议永久写入首次部署得到的 `workers.dev` Bootstrap URL：

```text
https://<worker>.workers.dev/bootstrap/v1/config
```

客户端不要写死：

```text
/api/v1/license/activate
/api/v1/license/validate
/api/v1/license/refresh
```

客户端只缓存经过签名验证后的：

```text
CanonicalBaseUrl
```

然后动态拼接 Endpoint。

## API

### 激活授权

```text
POST /api/v1/license/activate
```

请求示例：

```json
{
  "licenseKey": "CLC-XXXX-XXXX-XXXX-XXXX",
  "deviceId": "DEVICE-ID",
  "devicePublicKey": "-----BEGIN PUBLIC KEY-----...",
  "deviceName": "ThinkPad X13",
  "windowsVersion": "Windows 11",
  "appVersion": "1.0.0"
}
```

### Challenge

```text
POST /api/v1/device/challenge
```

### 设备签名验证

```text
POST /api/v1/device/verify
```

当前设备验证也使用 P-256 ECDSA 公钥。

## 后台主要功能

```text
仪表盘
授权管理
设备管理
操作日志
设置
```

授权管理当前支持：

```text
随机生成
自定义授权码
批量生成
永久授权
激活后 N 天
固定到期
设备上限
禁用
恢复
```

设备管理支持解绑设备。

## 当前需要你在 Cloudflare 完成的值

`wrangler.jsonc` 里还有两个占位值：

```text
TODO_D1_DATABASE_ID
TODO_TURNSTILE_SITE_KEY
```

这两个值拿到后替换即可。

Secrets 仍然只写入 Cloudflare，不写入源码。
