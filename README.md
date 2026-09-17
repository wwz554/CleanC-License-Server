# CleanC License Server

CleanC License Server 是一个基于 **Cloudflare Pages + Pages Functions + D1 + Turnstile** 的授权服务。

当前仓库已经改成 **Cloudflare Pages 直接连接 GitHub 自动部署** 的模式：

- 不再使用 GitHub Actions 部署；
- 不需要在仓库里填写 Cloudflare API Token；
- 不需要在仓库里填写 D1 `database_id`；
- 不需要手动执行 SQL migration；
- 只需要在 Cloudflare Pages 项目里绑定一个变量名为 `DB` 的 D1 数据库；
- 部署后的第一次请求会自动检查并创建所有数据表和索引；
- 后续再次部署不会清空原数据库，全部使用 `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`；
- 老版本数据库如果缺少 `device_challenges.license_id` 字段，代码也会自动补齐。

> 本仓库是公开仓库。管理员密码、Turnstile Secret、设备证明密钥、服务器签名私钥等敏感内容绝对不要提交到 GitHub。

---

# 一、项目结构

```text
CleanC-License-Server/
├─ functions/
│  ├─ index.ts            # Pages 根路由 /
│  └─ [[path]].ts         # Pages 所有其他路由
├─ public/
│  ├─ index.html          # Pages 静态输出目录占位文件
│  └─ _routes.json        # 所有请求交给 Pages Functions
├─ src/
│  ├─ admin.ts            # 管理后台页面
│  ├─ worker.ts           # 授权后端核心逻辑
│  ├─ pages.ts            # Pages 适配 + D1 自动建表
│  └─ webcrypto-compat.d.ts
├─ package.json
├─ tsconfig.json
└─ README.md
```

---

# 二、现在的部署方式

最终流程是：

```text
GitHub main 分支
       │
       │ push
       ▼
Cloudflare Pages Git Integration
       │
       ├─ npm install
       ├─ npm run build
       ├─ TypeScript 检查
       └─ 发布 Pages Functions
               │
               ▼
            D1 binding: DB
               │
               └─ 首次请求自动建表
```

以后修改 GitHub `main` 分支，Cloudflare Pages 会自动重新构建和发布。

Cloudflare 官方的 Pages Git Integration 支持 GitHub 仓库自动部署，每次向生产分支推送代码都会触发新部署。

---

# 三、第一次部署前需要准备什么

你只需要准备：

1. Cloudflare 账号；
2. GitHub 账号；
3. GitHub 仓库：`wwz554/CleanC-License-Server`；
4. 一个 Cloudflare D1 数据库；
5. 一个 Cloudflare Turnstile Widget；
6. 一组 P-256 服务器签名密钥。

不需要：

- GitHub Actions Secret；
- `CLOUDFLARE_API_TOKEN`；
- `CLOUDFLARE_ACCOUNT_ID`；
- 手动执行 D1 SQL；
- 手动运行 Wrangler deploy。

---

# 四、Cloudflare Pages 连接 GitHub

## 第 1 步：进入 Workers & Pages

登录 Cloudflare 控制台。

进入：

```text
Workers & Pages
```

选择：

```text
Create application
→ Pages
→ Connect to Git / Import an existing Git repository
```

如果 Cloudflare 第一次连接 GitHub，会要求安装 Cloudflare GitHub App。

授权时确保允许它访问：

```text
wwz554/CleanC-License-Server
```

然后选择这个仓库。

---

## 第 2 步：设置生产分支

Production branch 选择：

```text
main
```

---

## 第 3 步：设置构建参数

Framework preset：

```text
None
```

Build command：

```text
npm run build
```

Build output directory：

```text
public
```

Root directory：

```text
留空
```

也就是：

| 项目 | 填写内容 |
|---|---|
| Framework preset | None |
| Production branch | main |
| Build command | `npm run build` |
| Build output directory | `public` |
| Root directory | 留空 |

`npm run build` 实际执行 TypeScript 检查。如果代码存在 TypeScript 错误，Cloudflare 会直接判定本次构建失败，不会把错误版本发布出去。

---

## 第 4 步：第一次部署

点击：

```text
Save and Deploy
```

第一次部署此时即使成功，网站接口也可能返回：

```json
{
  "success": false,
  "code": "D1_BINDING_MISSING"
}
```

这是正常的，因为这时候还没有绑定 D1。

不要在 GitHub 代码里填写数据库 ID。

---

# 五、创建 D1 数据库

在 Cloudflare 控制台进入：

```text
Storage & Databases
→ D1 SQL Database
```

选择：

```text
Create database
```

数据库名称建议：

```text
cleanc-license
```

创建完成即可。

这里 **不需要手工建表，不需要打开 Console 执行 SQL，也不需要复制 database_id 到 GitHub**。

---

# 六、把 D1 绑定到 Pages

回到：

```text
Workers & Pages
→ 你的 CleanC Pages 项目
```

进入：

```text
Settings
→ Bindings
→ Add
→ D1 database
```

填写：

Variable name：

```text
DB
```

D1 database：

```text
选择刚才创建的 cleanc-license
```

注意：变量名必须严格写成：

```text
DB
```

不能写成：

```text
D1
DATABASE
CLEANC_DB
DB1
```

因为代码访问的是：

```ts
env.DB
```

Cloudflare 官方 Pages 文档也要求 Pages Functions 通过绑定变量名从 `context.env` 访问 D1。

---

# 七、D1 自动建表是怎么工作的

Pages Functions 每次新实例第一次收到请求时会进入：

```text
src/pages.ts
```

代码会自动检查并创建：

```text
licenses
devices
audit_logs
system_settings
domain_history
device_challenges
rate_limits
```

以及相关索引。

核心原则是：

```sql
CREATE TABLE IF NOT EXISTS ...
CREATE INDEX IF NOT EXISTS ...
```

因此：

- 新数据库：自动创建；
- 已经存在的数据库：不会删除；
- 已有授权码：不会丢失；
- 已有设备记录：不会清空；
- 再部署：不会重置数据库。

旧数据库如果 `device_challenges` 没有 `license_id`，代码会执行兼容升级：

```sql
ALTER TABLE device_challenges ADD COLUMN license_id TEXT
```

然后补建索引。

所以以后一般不需要再手动跑 migration。

---

# 八、绑定 D1 后必须重新部署

Cloudflare Pages 的 Binding 修改后，需要重新部署项目才能让当前部署使用新绑定。

进入：

```text
Deployments
```

找到最新 Production deployment。

选择：

```text
Retry deployment
```

或者直接在 GitHub 提交一个新 commit，也会自动重新部署。

部署完成后访问：

```text
https://你的项目.pages.dev/api/v1/health
```

正常应返回类似：

```json
{
  "status": "ok",
  "service": "cleanc-license-server",
  "apiVersion": 2
}
```

第一次请求同时会自动建立 D1 表结构。

---

# 九、创建 Turnstile

Cloudflare 控制台进入：

```text
Turnstile
```

选择：

```text
Add widget
```

Widget name 可以填写：

```text
CleanC License Admin
```

Hostname Management 中先加入你的 Pages 域名，例如：

```text
cleanc-license-server.pages.dev
```

以后绑定正式域名后，再把正式域名也加入 Turnstile Hostname Management。

创建完成后会得到两个值：

```text
Site Key
Secret Key
```

其中：

- Site Key 可以作为普通变量；
- Secret Key 必须作为加密 Secret。

---

# 十、配置 Pages Variables and Secrets

进入：

```text
Workers & Pages
→ CleanC Pages 项目
→ Settings
→ Variables and Secrets
→ Add
```

Cloudflare Pages 官方文档中，运行时环境变量和 Secret 都可以在这里配置。

## 普通变量

### APP_NAME

```text
APP_NAME
```

值：

```text
CleanC
```

### TURNSTILE_SITE_KEY

```text
TURNSTILE_SITE_KEY
```

值填 Turnstile 的 Site Key。

不要加密也可以，因为 Site Key 本身是前端公开值。

### LEASE_HOURS

```text
LEASE_HOURS
```

建议：

```text
72
```

代表授权租约默认 72 小时。

### BOOTSTRAP_BASE_URL

这个非常重要。

填写 Pages 自带的固定地址，例如：

```text
https://cleanc-license-server.pages.dev
```

不要在最后加 `/`。

这个地址作为 Windows 客户端的永久 Bootstrap 入口。

以后即使正式 API 域名变了，客户端仍然可以访问 Pages 地址获得最新主授权地址。

---

# 十一、需要设置的加密 Secret

以下变量添加时，请选择：

```text
Encrypt
```

不要作为普通明文变量。

## 1. ADMIN_PASSWORD

变量名：

```text
ADMIN_PASSWORD
```

值填写你自己的后台管理员密码。

不要写进 GitHub。

---

## 2. SESSION_SECRET

变量名：

```text
SESSION_SECRET
```

建议生成至少 48 字节随机值。

如果电脑有 OpenSSL：

```bash
openssl rand -base64 48
```

把输出完整复制进去。

---

## 3. DEVICE_PROOF_SECRET

变量名：

```text
DEVICE_PROOF_SECRET
```

再单独生成一个不同的随机值：

```bash
openssl rand -base64 48
```

不要和 SESSION_SECRET 使用同一个值。

---

## 4. TURNSTILE_SECRET

变量名：

```text
TURNSTILE_SECRET
```

值填写 Turnstile 的 Secret Key。

选择 Encrypt。

---

## 5. LICENSE_SIGNING_PRIVATE_KEY

这是服务器签发 Bootstrap 和 License Lease 的私钥。

变量名：

```text
LICENSE_SIGNING_PRIVATE_KEY
```

必须选择 Encrypt。

下面生成它。

---

# 十二、生成服务器 P-256 签名密钥

在 Git Bash / Linux / macOS 终端运行：

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ec-private-sec1.pem
openssl pkcs8 -topk8 -nocrypt -in ec-private-sec1.pem -out cleanc-private.pem
openssl pkey -in cleanc-private.pem -pubout -out cleanc-public.pem
```

最终得到：

```text
cleanc-private.pem
cleanc-public.pem
```

## cleanc-private.pem

内容类似：

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

完整复制到 Cloudflare Secret：

```text
LICENSE_SIGNING_PRIVATE_KEY
```

这个文件绝对不能上传 GitHub。

仓库 `.gitignore` 已经忽略：

```text
*.pem
*.key
*.p12
*.pfx
```

但仍然不要主动提交私钥。

## cleanc-public.pem

这是公钥，可以放入 CleanC Windows 客户端。

客户端用它验证服务器返回的：

```text
signedPayload
signature
```

服务器私钥永远只留在 Cloudflare Secret 中。

---

# 十三、配置完 Variables / Secrets 后重新部署

Secret 和 Binding 配置完成后，重新部署一次 Production。

进入：

```text
Deployments
→ 最新部署
→ Retry deployment
```

也可以向 GitHub `main` 推送新 commit，让 Cloudflare 自动部署。

---

# 十四、验证部署

假设你的 Pages 地址是：

```text
https://cleanc-license-server.pages.dev
```

依次测试：

## Health

```text
https://cleanc-license-server.pages.dev/api/v1/health
```

应返回：

```json
{
  "status": "ok",
  "service": "cleanc-license-server",
  "apiVersion": 2
}
```

## Meta

```text
https://cleanc-license-server.pages.dev/api/v1/meta
```

## Bootstrap

```text
https://cleanc-license-server.pages.dev/bootstrap/v1/config
```

应该能看到：

```text
apiVersion
canonicalBaseUrl
issuedAt
signedPayload
signature
```

## 管理后台

打开：

```text
https://cleanc-license-server.pages.dev/admin
```

应该出现 CleanC 管理登录页面。

登录需要：

```text
管理员密码 + Cloudflare Turnstile
```

---

# 十五、检查 D1 是否真的自动建表

进入：

```text
Cloudflare
→ D1
→ cleanc-license
→ Console / Explorer
```

此时应该可以看到这些表：

```text
licenses
devices
audit_logs
system_settings
domain_history
device_challenges
rate_limits
```

如果能看到，说明自动建表成功。

你不需要手动执行任何建表 SQL。

---

# 十六、以后 GitHub 怎么更新

Cloudflare Pages 已经和 GitHub 绑定以后：

```text
GitHub main
    ↓ push
Cloudflare 自动发现新 commit
    ↓
npm install
    ↓
npm run build
    ↓
Pages 自动部署
```

所以以后不需要：

```text
wrangler deploy
GitHub Actions
Cloudflare API Token
```

Cloudflare 官方 Pages Git Integration 本身负责拉取 GitHub 并自动部署。

---

# 十七、绑定正式域名

Pages 自带域名可以一直保留：

```text
https://xxxxx.pages.dev
```

它建议作为 Bootstrap 永久入口。

正式对外授权域名，例如：

```text
https://license.example.com
```

可以在 Pages 项目的 Custom domains 中绑定。

绑定完成后：

1. 确认：

```text
https://license.example.com/api/v1/health
```

可以正常访问；

2. 把：

```text
license.example.com
```

加入 Turnstile Hostname Management；

3. 打开：

```text
https://license.example.com/admin
```

4. 在设置页填写：

```text
https://license.example.com
```

5. 输入管理员密码并完成 Turnstile 二次验证；

6. 点击检测并保存。

之后：

```text
canonicalBaseUrl
```

会切换到正式域名。

而：

```text
BOOTSTRAP_BASE_URL
```

仍然保持：

```text
https://xxxxx.pages.dev
```

这样以后正式域名再次变化，Windows 客户端仍然有稳定入口。

---

# 十八、Windows 客户端推荐授权流程

## 首次激活

```text
客户端
 ↓
GET /bootstrap/v1/config
 ↓
使用内置服务器公钥验证 Bootstrap signature
 ↓
读取 canonicalBaseUrl
 ↓
本机生成 P-256 设备密钥对
 ↓
POST /api/v1/license/activate
 ↓
提交 licenseKey + deviceId + devicePublicKey
 ↓
服务器绑定设备并返回短期 License Lease
```

## 后续续租

```text
POST /api/v1/device/challenge
 ↓
服务器返回一次性 nonce
 ↓
Windows 本机私钥签名 nonce
 ↓
POST /api/v1/device/verify
 ↓
服务器验证设备公钥
 ↓
返回短时 deviceProof
 ↓
POST /api/v1/license/validate
或
POST /api/v1/license/refresh
 ↓
提交 deviceProof
 ↓
服务器签发新的 License Lease
```

因此只有：

```text
licenseKey + deviceId
```

不足以完成正常续租，还需要对应设备私钥。

---

# 十九、主要 API

```text
GET  /api/v1/health
GET  /api/v1/meta
GET  /bootstrap/v1/config
POST /api/v1/license/activate
POST /api/v1/license/validate
POST /api/v1/license/refresh
POST /api/v1/device/challenge
POST /api/v1/device/verify
```

管理后台：

```text
/admin
```

---

# 二十、常见问题

## 1. 返回 D1_BINDING_MISSING

原因：Pages 没有绑定 D1，或者绑定变量名不是 `DB`。

检查：

```text
Settings
→ Bindings
→ D1 database
```

变量名必须是：

```text
DB
```

然后重新部署。

---

## 2. 返回 D1_SCHEMA_INIT_FAILED

先确认：

- D1 数据库存在；
- Pages 确实绑定到了正确 D1；
- Production 环境也配置了绑定；
- 修改 Binding 后已经重新部署。

---

## 3. 管理后台 Turnstile 一直失败

检查 Turnstile Hostname Management 是否包含当前访问域名。

如果当前使用：

```text
xxxxx.pages.dev
```

就必须允许这个 hostname。

以后使用正式域名，也要把正式域名加入。

---

## 4. Cloudflare Pages 构建失败

确认构建设置：

```text
Build command: npm run build
Build output directory: public
Root directory: 留空
```

`npm run build` 会运行 TypeScript 检查，所以如果报 TS 错误，应先修代码再部署。

---

## 5. 为什么仓库里没有 wrangler.jsonc？

这是故意的。

当前目标是：

```text
Cloudflare Pages 控制台管理 Binding / Variables / Secrets
+
GitHub 直接自动部署
```

D1 不在仓库中声明，也不需要 database_id。

这样不会因为公开仓库泄漏环境配置，也减少 Worker 配置和 Pages Dashboard 配置互相冲突的风险。

---

## 6. 为什么没有 migrations 目录？

当前版本使用 `src/pages.ts` 自动维护基础数据库结构。

你创建一个空白 D1，绑定成 `DB` 后，第一次请求就会自动建立当前所需表结构。

---

# 二十一、上线前检查清单

请全部确认：

- [ ] Cloudflare Pages 已连接 `wwz554/CleanC-License-Server`
- [ ] Production branch = `main`
- [ ] Build command = `npm run build`
- [ ] Build output directory = `public`
- [ ] D1 数据库已创建
- [ ] D1 Binding 变量名 = `DB`
- [ ] `APP_NAME=CleanC`
- [ ] `TURNSTILE_SITE_KEY` 已设置
- [ ] `LEASE_HOURS=72`
- [ ] `BOOTSTRAP_BASE_URL=https://你的项目.pages.dev`
- [ ] `ADMIN_PASSWORD` 使用 Secret
- [ ] `SESSION_SECRET` 使用 Secret
- [ ] `DEVICE_PROOF_SECRET` 使用 Secret
- [ ] `TURNSTILE_SECRET` 使用 Secret
- [ ] `LICENSE_SIGNING_PRIVATE_KEY` 使用 Secret
- [ ] Turnstile 已允许 pages.dev hostname
- [ ] 重新部署 Production
- [ ] `/api/v1/health` 正常
- [ ] `/bootstrap/v1/config` 正常
- [ ] `/admin` 可以打开
- [ ] D1 已自动出现 7 张表
- [ ] 服务器签名公钥已经嵌入 Windows 客户端

---

# 二十二、安全说明

没有任何纯客户端软件能够做到“绝对无法破解”。CleanC License Server 的安全目标是：

- 授权状态由服务器决定；
- 服务端私钥永远不进入 Windows 客户端；
- 客户端只保存服务器公钥；
- License Lease 有有效期；
- 设备私钥参与后续续租；
- challenge 一次性使用；
- deviceProof 有短有效期；
- 管理后台使用 Session + CSRF + Turnstile；
- 管理敏感操作进行二次验证；
- 敏感变量只放 Cloudflare Secrets。

对于当前项目，推荐始终保留：

```text
pages.dev = Bootstrap 固定入口
正式自定义域名 = canonicalBaseUrl 主授权 API
```

这样最便于以后换域名，同时也最不容易导致已经发布的 CleanC 客户端失联。
