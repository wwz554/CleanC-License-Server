# CleanC License Server

CleanC License Server 是一个基于 **Cloudflare Workers + D1 + Turnstile** 的授权服务，包含管理员 Web 控制台、授权码管理、设备绑定、设备签名验证、短期租约、动态主域名以及 GitHub Actions 自动部署。

> 本仓库是公开仓库。**管理员密码、Turnstile Secret、签名私钥、Cloudflare API Token 等敏感内容绝对不要写进代码或提交到 GitHub。** 它们必须放在 Cloudflare Secret 或 GitHub Actions Secret 中。

---

## 一、当前架构

```text
CleanC Windows 客户端
        │
        │  Bootstrap / API
        ▼
Cloudflare Worker
        │
        ├── 管理后台 /admin
        ├── 授权 API /api/v1/*
        ├── Bootstrap /bootstrap/v1/config
        ├── Turnstile 服务端校验
        └── D1 数据库
                ├── licenses
                ├── devices
                ├── device_challenges
                ├── audit_logs
                ├── rate_limits
                └── system_settings
```

核心文件：

```text
src/index.ts          Worker 入口，仅转发到 worker.ts
src/worker.ts         后端、授权、安全、D1、API
src/admin.ts          管理后台页面
migrations/           D1 数据库迁移
wrangler.jsonc        Cloudflare Worker 配置
.github/workflows/    GitHub Actions 自动部署
```

---

## 二、代码审查后已经修正的关键问题

这次对仓库代码逐段检查后做了以下调整：

1. **把原来超过 4 万字符的单文件拆分**为 `index.ts + worker.ts + admin.ts`，以后检查、维护和 GitHub 读取都更稳定。
2. **设备签名不再只是“摆设”**。现在 `validate/refresh` 必须带设备私钥签名后换取的短期 `deviceProof`，仅知道 `licenseKey + deviceId` 不能直接续租。
3. 设备 challenge 现在同时绑定 **licenseId + deviceId**，避免同一个 deviceId 出现在不同授权下造成验证歧义。
4. 激活时强制校验设备提交的 **P-256 SPKI 公钥**；已绑定设备再次激活时，公钥不一致会拒绝。
5. challenge 是一次性的，成功使用后写入 `used_at`，防止重复使用。
6. `deviceProof` 使用 HMAC 保护，默认 10 分钟有效，只能用于对应授权和设备。
7. Worker 返回的 Bootstrap 和租约增加 `signedPayload`，Windows 客户端可以直接验证服务器签名的原始字节，避免不同语言 JSON 序列化顺序造成验签不一致。
8. 登录限流改为单条 D1 UPSERT + RETURNING，减少并发条件下的计数竞争。
9. 管理后台增加退出登录接口，并清除 Session Cookie。
10. 自定义主域名检测不再只判断 `/health = ok`，还要求返回 CleanC 服务标识，避免误把其他网站设成授权服务器。
11. 随机授权码生成去掉简单取模带来的轻微分布偏差。
12. 批量授权码单次最大调整为 **15 个**，避免 Cloudflare D1 免费版单次 Worker 调用查询数量限制。需要更多授权码时连续生成多批即可。
13. `BOOTSTRAP_BASE_URL` 改为必须显式配置的固定 `workers.dev` 地址，确保以后更换正式域名时客户端仍有稳定的兜底入口。
14. GitHub Actions 在部署前会主动检查 D1 ID、Turnstile Site Key、Bootstrap 地址和 Cloudflare CI 凭据，缺任何一项都会给出明确错误。

> 没有任何网络授权系统能够做到“绝对无法破解”。这里的设计目标是：服务器拥有最终授权权威、客户端不保存服务器私钥、租约有时效、设备私钥参与续租，并尽量提高伪造和复制授权的成本。

---

# 三、Cloudflare 从零搭建：保姆级教程

下面按第一次部署的顺序操作。建议严格按顺序执行。

## 第 0 步：准备内容

你需要：

- 一个 Cloudflare 账号；
- 一个 GitHub 账号；
- 本仓库；
- Windows 电脑安装 Node.js 20 或 22；
- Git；
- OpenSSL。Git for Windows 自带的 Git Bash 通常可直接使用 OpenSSL。

确认 Node.js：

```powershell
node -v
npm -v
```

---

## 第 1 步：把仓库克隆到电脑

打开 PowerShell：

```powershell
git clone https://github.com/wwz554/CleanC-License-Server.git
cd CleanC-License-Server
npm install
```

检查 TypeScript：

```powershell
npm run typecheck
```

正常情况下不应出现 TypeScript 错误。

---

## 第 2 步：登录 Cloudflare Wrangler

执行：

```powershell
npx wrangler login
```

浏览器会打开 Cloudflare 授权页面。

登录你的 Cloudflare 账号后点 **Allow / 允许**。

确认登录状态：

```powershell
npx wrangler whoami
```

---

## 第 3 步：确认 workers.dev 子域名

Cloudflare Dashboard：

```text
Workers & Pages
→ Overview
→ 右侧或顶部查看 Your subdomain
```

假设你的 Cloudflare Workers 子域名是：

```text
abc123.workers.dev
```

本项目 Worker 名称固定是：

```text
cleanc-license-server
```

那么最终默认 Worker 地址就是：

```text
https://cleanc-license-server.abc123.workers.dev
```

记住这个地址，后面配置 `BOOTSTRAP_BASE_URL` 和 Turnstile 都要使用。

**不要关闭 workers.dev。**

这个地址是 CleanC 客户端的长期 Bootstrap 兜底地址。正式域名以后可以换，但是 Bootstrap 建议一直保留。

---

## 第 4 步：创建 D1 数据库

在项目目录运行：

```powershell
npx wrangler d1 create cleanc-license
```

Cloudflare 会返回类似：

```text
database_name = "cleanc-license"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

复制 `database_id`。

打开：

```text
wrangler.jsonc
```

找到：

```json
"database_id": "TODO_D1_DATABASE_ID"
```

替换成真实 D1 ID，例如：

```json
"database_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

不要修改：

```json
"binding": "DB"
```

Worker 代码就是通过 `env.DB` 使用这个数据库。

---

## 第 5 步：创建 Turnstile

进入 Cloudflare Dashboard：

```text
Turnstile
→ Add widget
```

建议：

```text
Widget name: CleanC License Admin
Widget mode: Managed
```

Hostname Management 里首先加入你的 workers.dev 主机名，例如：

```text
cleanc-license-server.abc123.workers.dev
```

只填主机名，不要填写：

```text
https://
/admin
/
```

创建后 Cloudflare 会给你两个值：

```text
Site Key
Secret Key
```

### Site Key

Site Key 是公开值，可以放在 `wrangler.jsonc`。

找到：

```json
"TURNSTILE_SITE_KEY": "TODO_TURNSTILE_SITE_KEY"
```

替换为实际 Site Key。

### Secret Key

Secret Key 是私密值。

**绝对不要写进 GitHub。**

后面使用：

```powershell
npx wrangler secret put TURNSTILE_SECRET
```

录入。

Cloudflare 官方要求 Turnstile 必须进行服务端 Siteverify 校验；本项目已经实现，并且还会检查返回的 hostname 是否与当前管理后台域名一致。

---

## 第 6 步：填写固定 Bootstrap 地址

打开：

```text
wrangler.jsonc
```

找到：

```json
"BOOTSTRAP_BASE_URL": "TODO_BOOTSTRAP_BASE_URL"
```

替换为第 3 步得到的完整 Worker 地址，例如：

```json
"BOOTSTRAP_BASE_URL": "https://cleanc-license-server.abc123.workers.dev"
```

结尾不要加 `/`。

正确：

```text
https://cleanc-license-server.abc123.workers.dev
```

不建议：

```text
https://cleanc-license-server.abc123.workers.dev/
```

---

## 第 7 步：生成服务器 P-256 签名密钥

这个私钥用于服务器给 Bootstrap 配置和 License Lease 签名。

Windows 推荐打开 **Git Bash**，进入项目目录执行：

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ec-private-sec1.pem
openssl pkcs8 -topk8 -nocrypt -in ec-private-sec1.pem -out cleanc-private.pem
openssl pkey -in cleanc-private.pem -pubout -out cleanc-public.pem
```

得到：

```text
cleanc-private.pem   服务器私钥
cleanc-public.pem    客户端公钥
```

### cleanc-private.pem

只能放 Cloudflare Secret。

**绝对不要上传 GitHub。**

### cleanc-public.pem

可以嵌入 CleanC Windows 客户端，用来验证服务器签名。

客户端必须只信任你内置的服务器公钥，而不是从授权服务器下载一个新的公钥再信任，否则攻击者替换服务器时也可以同时替换公钥。

---

## 第 8 步：生成两个随机 Secret

在 Git Bash 执行两次：

```bash
openssl rand -base64 48
```

分别用作：

```text
SESSION_SECRET
DEVICE_PROOF_SECRET
```

它们必须是两个不同的随机值。

不要使用简单密码，也不要与管理员密码相同。

---

## 第 9 步：第一次部署 Worker

先执行数据库迁移：

```powershell
npm run db:remote
```

或者：

```powershell
npx wrangler d1 migrations apply cleanc-license --remote
```

确认时输入 `y`。

然后先部署一次 Worker：

```powershell
npm run deploy
```

或者：

```powershell
npx wrangler deploy
```

Cloudflare 应返回类似：

```text
https://cleanc-license-server.abc123.workers.dev
```

此时 Worker 已存在，下一步马上添加 Secrets。

> 在 Secrets 配好之前，不要把这个服务当作正式可用服务。

---

## 第 10 步：添加 5 个 Cloudflare Secrets

依次执行：

```powershell
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put SESSION_SECRET
npx wrangler secret put DEVICE_PROOF_SECRET
npx wrangler secret put TURNSTILE_SECRET
npx wrangler secret put LICENSE_SIGNING_PRIVATE_KEY
```

### ADMIN_PASSWORD

这里输入你希望管理后台使用的密码。

不要把密码写入 README、`wrangler.jsonc` 或源码。

### SESSION_SECRET

粘贴第 8 步生成的第一个随机值。

### DEVICE_PROOF_SECRET

粘贴第 8 步生成的第二个随机值。

### TURNSTILE_SECRET

粘贴 Cloudflare Turnstile 的 Secret Key。

### LICENSE_SIGNING_PRIVATE_KEY

需要粘贴 `cleanc-private.pem` 的完整内容，包括：

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

Cloudflare Wrangler 支持多行 Secret。

完成后建议再部署一次：

```powershell
npm run deploy
```

---

## 第 11 步：检查服务是否正常

浏览器打开：

```text
https://你的workers地址/api/v1/health
```

应该看到类似：

```json
{
  "status": "ok",
  "service": "cleanc-license-server",
  "apiVersion": 2
}
```

再打开：

```text
https://你的workers地址/api/v1/meta
```

然后打开管理后台：

```text
https://你的workers地址/admin
```

应该出现 CleanC 管理员登录页面和 Cloudflare Turnstile。

如果 Turnstile 不显示或提示域名错误，优先检查 Turnstile 的 Hostname Management 是否包含：

```text
cleanc-license-server.你的workers子域.workers.dev
```

---

# 四、绑定正式域名

没有正式域名也完全可以先使用 workers.dev。

等你以后有域名，例如：

```text
license.example.com
```

按下面操作。

## 第 1 步：域名必须在 Cloudflare 中

Custom Domain 要求目标域名所在 Zone 已经添加到 Cloudflare。

## 第 2 步：给 Worker 添加 Custom Domain

Cloudflare Dashboard：

```text
Workers & Pages
→ cleanc-license-server
→ Settings
→ Domains & Routes
→ Add
→ Custom Domain
```

填：

```text
license.example.com
```

点击添加。

Cloudflare 会自动处理对应 DNS 记录和证书。

如果这个主机名原来已经存在冲突的 CNAME，需要先处理冲突记录。

## 第 3 步：Turnstile 加入新域名

进入：

```text
Turnstile
→ CleanC License Admin
→ Settings
→ Hostname Management
```

保留原 workers.dev 主机名，同时增加：

```text
license.example.com
```

不要删除 workers.dev，否则你以后通过 Bootstrap 地址进入管理后台时 Turnstile 会失效。

## 第 4 步：测试新域名

先打开：

```text
https://license.example.com/api/v1/health
```

必须返回：

```json
{
  "status": "ok",
  "service": "cleanc-license-server",
  "apiVersion": 2
}
```

## 第 5 步：在 CleanC 后台切换主授权地址

打开：

```text
https://license.example.com/admin
```

登录后：

```text
设置
→ 域名与 API
```

填：

```text
license.example.com
```

再次输入管理员密码并完成 Turnstile，然后点击：

```text
检测并保存
```

系统会主动访问：

```text
https://license.example.com/api/v1/health
```

并确认它确实是 CleanC License Server，然后写入 D1：

```text
PRIMARY_BASE_URL
```

从此 Bootstrap 返回的 `canonicalBaseUrl` 会自动变成：

```text
https://license.example.com
```

但是固定 Bootstrap 地址仍然是：

```text
https://cleanc-license-server.xxx.workers.dev/bootstrap/v1/config
```

这样以后正式域名发生变化，Windows 客户端仍然有一个固定入口可以获得新地址。

---

# 五、GitHub Actions 自动部署

仓库中已经包含：

```text
.github/workflows/deploy.yml
```

每次修改以下内容并推送 `main`：

```text
src/**
migrations/**
wrangler.jsonc
package.json
.github/workflows/deploy.yml
```

GitHub 会自动：

```text
npm install
→ TypeScript 检查
→ 检查 Cloudflare 配置
→ 应用 D1 migration
→ 部署 Worker
```

README 修改不会触发生产部署。

## 创建 Cloudflare API Token

Cloudflare Dashboard 中进入 API Token 页面。

创建给 GitHub Actions 使用的专用 Token。

最少需要允许它：

- 部署/编辑这个 Worker；
- 执行 D1 migration；
- 读取必要的账户信息。

Cloudflare 当前权限界面可能显示为 Workers 的 `Editor` / `Workers Scripts Edit` 和 D1 的 `Editor/Edit`。只给这个 CI 所需的最小权限，不要直接使用 Global API Key。

Cloudflare 官方对 GitHub Actions 的要求是 CI 中提供：

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

API Token 只显示一次，请妥善保存。

## 找 Account ID

Cloudflare Dashboard 中选择对应账户，在账户信息位置找到：

```text
Account ID
```

## 在 GitHub 添加 Actions Secrets

进入 GitHub 仓库：

```text
Settings
→ Secrets and variables
→ Actions
→ New repository secret
```

创建：

```text
CLOUDFLARE_API_TOKEN
```

值填 Cloudflare API Token。

再创建：

```text
CLOUDFLARE_ACCOUNT_ID
```

值填 Cloudflare Account ID。

**Cloudflare API Token 不要发到 Issue、README、代码或聊天截图里。**

完成后进入：

```text
GitHub
→ Actions
→ Deploy Cloudflare Worker
→ Run workflow
```

手动执行一次。

如果 Actions 在：

```text
Verify Cloudflare configuration
```

失败，按照错误提示检查三个占位符是否都已经替换：

```text
TODO_D1_DATABASE_ID
TODO_TURNSTILE_SITE_KEY
TODO_BOOTSTRAP_BASE_URL
```

以及两个 GitHub Secret 是否已添加。

---

# 六、Windows 客户端正确授权流程

## 首次激活

客户端第一次启动时自己生成 P-256 密钥对。

私钥只保存在本机安全存储中，**永远不上传服务器**。

公钥使用 SPKI PEM 格式上传服务器。

请求：

```http
POST /api/v1/license/activate
Content-Type: application/json
```

示例：

```json
{
  "licenseKey": "CLC-XXXX-XXXX-XXXX-XXXX",
  "deviceId": "稳定的设备标识",
  "devicePublicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "deviceName": "DESKTOP-ABC",
  "windowsVersion": "Windows 11",
  "appVersion": "1.0.0"
}
```

成功后服务器返回短期 License Lease、`signedPayload` 和 `signature`。

客户端必须用内置的 `cleanc-public.pem` 验证服务器签名后才信任 Lease。

## 后续验证 / 续租

不能直接调用 validate/refresh。

正确顺序：

```text
1. POST /api/v1/device/challenge
2. 客户端用本机 P-256 私钥签 nonce
3. POST /api/v1/device/verify
4. 服务端验证签名
5. 服务端返回短期 deviceProof
6. POST /api/v1/license/validate 或 /refresh
7. 请求中携带 deviceProof
8. 服务端返回新的签名 Lease
```

### challenge

```json
{
  "licenseKey": "CLC-XXXX-XXXX-XXXX-XXXX",
  "deviceId": "设备ID"
}
```

### verify

```json
{
  "licenseKey": "CLC-XXXX-XXXX-XXXX-XXXX",
  "deviceId": "设备ID",
  "nonce": "challenge返回的nonce",
  "signature": "Base64URL格式的ECDSA签名"
}
```

成功后返回：

```json
{
  "success": true,
  "verified": true,
  "deviceProof": "...",
  "proofExpiresInSeconds": 600
}
```

### validate / refresh

```json
{
  "licenseKey": "CLC-XXXX-XXXX-XXXX-XXXX",
  "deviceId": "设备ID",
  "deviceProof": "verify返回的deviceProof",
  "appVersion": "1.0.0",
  "windowsVersion": "Windows 11"
}
```

如果复制了授权码和 deviceId，但是没有原设备私钥，就无法获得有效的 `deviceProof`。

---

# 七、Bootstrap 与服务器签名

客户端应内置固定 Bootstrap：

```text
https://cleanc-license-server.xxx.workers.dev/bootstrap/v1/config
```

返回示例：

```json
{
  "apiVersion": 2,
  "canonicalBaseUrl": "https://license.example.com",
  "issuedAt": "...",
  "signedPayload": "...",
  "signature": "..."
}
```

推荐客户端验签方式：

```text
1. Base64URL 解码 signedPayload
2. 使用内置服务器 P-256 公钥验证 signature
3. 验签成功后解析 signedPayload 中的 JSON
4. 只使用验签后的 canonicalBaseUrl
```

不要先相信外层的 `canonicalBaseUrl` 再验签。

License Lease 也使用同样的 `signedPayload + signature` 方式。

---

# 八、管理后台功能

访问：

```text
https://你的域名/admin
```

当前支持：

- 管理员密码登录；
- Cloudflare Turnstile；
- HttpOnly / Secure / SameSite=Strict Session；
- CSRF；
- 登录限流；
- 随机授权码；
- 自定义授权码；
- 批量生成；
- 永久授权；
- 激活后 N 天；
- 固定到期时间；
- 最大设备数；
- 禁用 / 恢复授权；
- 查看设备；
- 解绑设备；
- 操作日志；
- 动态主授权域名；
- 域名二次密码 + Turnstile 验证；
- 退出登录。

随机授权码格式：

```text
CLC-XXXX-XXXX-XXXX-XXXX
```

字符集主动排除了容易混淆的：

```text
0 O 1 I L
```

---

# 九、常见报错

## `TODO_D1_DATABASE_ID` 未替换

说明 `wrangler.jsonc` 还没有真实 D1 ID。

运行：

```powershell
npx wrangler d1 create cleanc-license
```

复制返回的 `database_id`。

## `TODO_TURNSTILE_SITE_KEY` 未替换

进入 Cloudflare Turnstile 创建 Widget，并把 Site Key 写入 `wrangler.jsonc`。

## `TODO_BOOTSTRAP_BASE_URL` 未替换

填写：

```text
https://cleanc-license-server.你的workers子域.workers.dev
```

## GitHub Actions 提示 `CLOUDFLARE_API_TOKEN` 为空

GitHub：

```text
Settings → Secrets and variables → Actions
```

添加：

```text
CLOUDFLARE_API_TOKEN
```

## `CLOUDFLARE_ACCOUNT_ID` 为空

同样在 GitHub Actions Secret 添加 Cloudflare Account ID。

## 管理后台 Turnstile 一直失败

检查：

```text
Turnstile → Widget → Settings → Hostname Management
```

当前浏览器正在访问的 hostname 必须存在于允许列表中。

## 自定义域名提示 `DOMAIN_NOT_READY`

先确认：

```text
https://你的正式域名/api/v1/health
```

可以直接访问，并且包含：

```json
"service": "cleanc-license-server"
```

## `DEVICE_KEY_MISMATCH`

说明同一个 license + deviceId 已经绑定过另一把公钥。

正常更换设备或重装导致密钥丢失时，应先在管理后台解绑旧设备，再重新激活。

## `DEVICE_PROOF_REQUIRED`

说明客户端没有先完成：

```text
challenge → sign → verify
```

或者 deviceProof 已超过 10 分钟。

---

# 十、安全注意事项

永远不要提交这些内容：

```text
ADMIN_PASSWORD
SESSION_SECRET
DEVICE_PROOF_SECRET
TURNSTILE_SECRET
LICENSE_SIGNING_PRIVATE_KEY
CLOUDFLARE_API_TOKEN
```

如果任何一个敏感值曾经出现在公开 GitHub commit 中，不是“删掉当前文件”就安全了，因为旧 commit 仍可能保留它。应该立即轮换对应 Secret。

特别重要：

- `cleanc-private.pem` 永远只属于服务器；
- `cleanc-public.pem` 才能进入 Windows 客户端；
- 设备私钥永远只属于具体 Windows 设备；
- Worker 不应该返回服务器私钥；
- Windows 客户端不要把“服务器返回的公钥”当信任根；
- 正式使用建议保留 workers.dev Bootstrap，但业务授权请求走自己的 Custom Domain；
- GitHub Actions 使用最小权限 API Token，不要使用 Global API Key。

---

# 十一、官方 Cloudflare 文档

Cloudflare Workers：

https://developers.cloudflare.com/workers/

Wrangler 配置：

https://developers.cloudflare.com/workers/wrangler/configuration/

D1：

https://developers.cloudflare.com/d1/

D1 migrations：

https://developers.cloudflare.com/d1/reference/migrations/

Workers Secrets：

https://developers.cloudflare.com/workers/configuration/secrets/

Turnstile：

https://developers.cloudflare.com/turnstile/

Turnstile 服务端验证：

https://developers.cloudflare.com/turnstile/get-started/server-side-validation/

Workers Custom Domains：

https://developers.cloudflare.com/workers/configuration/routing/custom-domains/

GitHub Actions：

https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/

---

## 最终上线检查清单

部署前逐项确认：

- [ ] `npm run typecheck` 通过
- [ ] D1 已创建
- [ ] `TODO_D1_DATABASE_ID` 已替换
- [ ] Turnstile 已创建
- [ ] workers.dev hostname 已加入 Turnstile
- [ ] `TODO_TURNSTILE_SITE_KEY` 已替换
- [ ] `TODO_BOOTSTRAP_BASE_URL` 已替换
- [ ] D1 migrations 已执行
- [ ] `ADMIN_PASSWORD` 已配置为 Cloudflare Secret
- [ ] `SESSION_SECRET` 已配置
- [ ] `DEVICE_PROOF_SECRET` 已配置
- [ ] `TURNSTILE_SECRET` 已配置
- [ ] `LICENSE_SIGNING_PRIVATE_KEY` 已配置
- [ ] `cleanc-public.pem` 已安全嵌入 Windows 客户端
- [ ] `/api/v1/health` 正常
- [ ] `/admin` 可登录
- [ ] 可以生成授权码
- [ ] 首次激活成功
- [ ] challenge / verify 成功
- [ ] validate / refresh 必须带 deviceProof
- [ ] GitHub Actions 两个 Cloudflare Secret 已配置
- [ ] 如使用正式域名，Custom Domain 和 Turnstile Hostname 都已配置

完成以上项目后，CleanC License Server 才算真正进入可用状态。
