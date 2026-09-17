# CleanC License Server

CleanC License Server 是给 CleanC Windows 客户端使用的授权服务端，基于 **Cloudflare Workers + D1 + Turnstile**。

它包含：

- 管理后台 `/admin`
- 管理员密码 + Cloudflare Turnstile 双重登录验证
- 随机授权码、自定义授权码、批量生成
- 永久授权、激活后 N 天、固定到期时间
- 每个授权码可限制设备数量
- 设备绑定、解绑、重新绑定
- 授权禁用 / 恢复
- 操作审计日志
- P-256 / ECDSA 数字签名租约
- 设备 Challenge / Verify 验证
- 动态主授权域名
- 稳定 Bootstrap 地址
- GitHub Actions 自动部署

> **非常重要：** 不要把管理员密码、Turnstile Secret、签名私钥、Cloudflare API Token 写进 GitHub 代码。它们必须放在 Cloudflare Secret 或 GitHub Actions Secret 中。

---

# 1. 项目结构

```text
CleanC-License-Server/
├─ .github/
│  └─ workflows/
│     └─ deploy.yml
├─ migrations/
│  └─ 0001_init.sql
├─ src/
│  └─ index.ts
├─ .env.example
├─ .gitignore
├─ package.json
├─ tsconfig.json
├─ wrangler.jsonc
└─ README.md
```

核心组件：

| 组件 | 用途 |
|---|---|
| Cloudflare Worker | 运行授权 API 和后台管理网页 |
| Cloudflare D1 | 保存授权码、设备、日志、系统设置 |
| Cloudflare Turnstile | 管理员登录和修改域名时的人机验证 |
| Cloudflare Secret | 保存管理员密码、Session Secret、Turnstile Secret、授权签名私钥 |
| GitHub Actions | main 分支更新后自动执行 TypeScript 检查、D1 Migration 和 Worker 部署 |

---

# 2. 当前主要 API

客户端接口：

```text
POST /api/v1/license/activate
POST /api/v1/license/validate
POST /api/v1/license/refresh
POST /api/v1/device/challenge
POST /api/v1/device/verify
GET  /api/v1/health
GET  /api/v1/meta
GET  /bootstrap/v1/config
```

后台：

```text
/admin
```

健康检查：

```text
https://你的-worker地址/api/v1/health
```

正常返回示例：

```json
{
  "status": "ok",
  "apiVersion": 1
}
```

---

# 3. 授权逻辑说明

## 3.1 激活

客户端第一次提交：

```json
{
  "licenseKey": "CLC-XXXX-XXXX-XXXX-XXXX",
  "deviceId": "设备唯一ID",
  "devicePublicKey": "设备P-256公钥PEM",
  "deviceName": "DESKTOP-XXXX",
  "windowsVersion": "Windows 11",
  "appVersion": "1.0.0"
}
```

服务端会：

1. 检查授权码是否存在。
2. 检查授权是否被禁用。
3. 检查授权是否已经过期。
4. 检查设备数量是否超过上限。
5. 绑定设备。
6. 如果是“激活后 N 天”，从第一次激活开始计算到期时间。
7. 生成带 ECDSA P-256 签名的短期 Lease。

## 3.2 Validate / Refresh

`validate` 和 `refresh` **不会自动新增设备绑定**。

设备必须已经通过 `activate` 完成绑定，否则返回：

```text
DEVICE_NOT_BOUND
```

这样可以避免有人把 validate/refresh 当成第二个激活接口绕过原始激活流程。

## 3.3 Lease 到期时间

默认：

```text
LEASE_HOURS = 72
```

也就是每次服务端签发的短期 Lease 最多 72 小时。

如果授权本身比 72 小时更早到期，Lease 会自动缩短到授权的实际到期时间，不会出现“授权已经过期，但旧 Lease 还能继续有效几天”的问题。

## 3.4 设备解绑

后台点“解绑”后：

- 释放设备名额；
- 原设备记录保留用于审计；
- 同一设备以后允许重新激活绑定。

---

# 4. Cloudflare 从零部署——保姆级教程

下面按第一次部署的实际顺序操作。

---

# 5. 第一步：准备 Cloudflare 账号

打开：

```text
https://dash.cloudflare.com/
```

登录你的 Cloudflare 账号。

后面会用到：

- Workers & Pages
- D1
- Turnstile
- API Tokens

如果暂时没有自己的域名，也完全可以先部署。

第一次先使用 Cloudflare 自动分配的：

```text
xxxx.workers.dev
```

以后有域名再绑定。

---

# 6. 第二步：安装 Node.js

电脑建议安装 Node.js 22 LTS 或当前稳定版。

检查：

```bash
node -v
npm -v
```

如果能看到版本号即可。

---

# 7. 第三步：下载 GitHub 项目

```bash
git clone https://github.com/wwz554/CleanC-License-Server.git
cd CleanC-License-Server
npm install
```

检查 TypeScript：

```bash
npm run typecheck
```

如果没有报错，说明代码可以通过 TypeScript 静态检查。

---

# 8. 第四步：登录 Wrangler

执行：

```bash
npx wrangler login
```

浏览器会打开 Cloudflare 授权页面。

选择你的 Cloudflare 账号并授权。

登录成功以后可以执行：

```bash
npx wrangler whoami
```

确认当前 Cloudflare 账号。

---

# 9. 第五步：创建 D1 数据库

在项目目录执行：

```bash
npx wrangler d1 create cleanc-license
```

Cloudflare 会返回类似：

```text
database_name = "cleanc-license"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

请复制 `database_id`。

打开：

```text
wrangler.jsonc
```

找到：

```json
"database_id": "TODO_D1_DATABASE_ID"
```

改成真实 ID：

```json
"database_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

注意：

- 这里的 Database ID 不是密码，可以写进仓库；
- 不要改 `binding: "DB"`；
- 不要改数据库名 `cleanc-license`，除非你同时修改 GitHub Actions 和脚本。

---

# 10. 第六步：创建 Turnstile

Cloudflare 控制台进入：

```text
Turnstile
```

点击：

```text
Add widget
```

名称可以填写：

```text
CleanC License Server
```

Widget Mode 建议：

```text
Managed
```

第一次部署时还不知道最终 workers.dev 地址，可以先完成 Worker 第一次部署后，再回来把真实 hostname 添加进去。

创建成功后你会得到：

```text
Site Key
Secret Key
```

两者用途不同。

## Site Key

Site Key 可以公开，写入：

```text
wrangler.jsonc
```

找到：

```json
"TURNSTILE_SITE_KEY": "TODO_TURNSTILE_SITE_KEY"
```

替换成你的真实 Site Key。

## Secret Key

Secret Key 绝对不要写进 GitHub。

后面使用：

```bash
npx wrangler secret put TURNSTILE_SECRET
```

保存。

---

# 11. 第七步：生成授权签名 P-256 密钥

这个密钥非常重要。

服务端保存：

```text
私钥
```

Windows CleanC 客户端内置：

```text
公钥
```

客户端利用公钥验证服务端 Lease 是否真的由你的服务器签发。

## Windows 有 OpenSSL 的情况

执行：

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ec-private-sec1.pem
openssl pkcs8 -topk8 -nocrypt -in ec-private-sec1.pem -out cleanc-private.pem
openssl pkey -in cleanc-private.pem -pubout -out cleanc-public.pem
```

会生成：

```text
cleanc-private.pem
cleanc-public.pem
```

### cleanc-private.pem

只放 Cloudflare Secret。

绝对不要：

- 上传 GitHub
- 放 Windows 客户端
- 发给别人
- 写进 README

### cleanc-public.pem

可以放 CleanC Windows 客户端中。

客户端只需要公钥，不能使用私钥。

---

# 12. 第八步：配置四个 Cloudflare Secret

项目需要四个 Secret：

```text
ADMIN_PASSWORD
SESSION_SECRET
TURNSTILE_SECRET
LICENSE_SIGNING_PRIVATE_KEY
```

## 12.1 ADMIN_PASSWORD

执行：

```bash
npx wrangler secret put ADMIN_PASSWORD
```

终端提示输入时，输入你的后台管理员密码。

不要把真实管理员密码提交到 GitHub。

## 12.2 SESSION_SECRET

先生成一段随机值：

```bash
openssl rand -base64 48
```

复制结果。

然后：

```bash
npx wrangler secret put SESSION_SECRET
```

粘贴刚才生成的随机字符串。

## 12.3 TURNSTILE_SECRET

```bash
npx wrangler secret put TURNSTILE_SECRET
```

输入 Turnstile 的 Secret Key。

## 12.4 LICENSE_SIGNING_PRIVATE_KEY

执行：

```bash
npx wrangler secret put LICENSE_SIGNING_PRIVATE_KEY
```

输入 `cleanc-private.pem` 的完整内容，包括：

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

如果命令行多行粘贴不方便，也可以在 Cloudflare Worker 控制台：

```text
Workers & Pages
→ 你的 Worker
→ Settings
→ Variables and Secrets
→ Add
→ Secret
```

手工添加。

---

# 13. 第九步：初始化 D1 表结构

项目已经包含：

```text
migrations/0001_init.sql
```

执行远程 Migration：

```bash
npm run db:remote
```

等价于：

```bash
npx wrangler d1 migrations apply cleanc-license --remote
```

看到 Migration 成功即可。

数据库会创建：

```text
licenses
devices
audit_logs
system_settings
domain_history
device_challenges
rate_limits
```

---

# 14. 第十步：第一次部署 Worker

执行：

```bash
npm run deploy
```

或者：

```bash
npx wrangler deploy
```

成功后 Wrangler 会显示一个 Worker 地址，例如：

```text
https://cleanc-license-server.xxxxx.workers.dev
```

请保存这个地址。

---

# 15. 第十一步：测试 Worker

浏览器打开：

```text
https://cleanc-license-server.xxxxx.workers.dev/api/v1/health
```

正常应该显示：

```json
{
  "status": "ok",
  "apiVersion": 1
}
```

然后打开：

```text
https://cleanc-license-server.xxxxx.workers.dev/admin
```

应该看到 CleanC License 管理后台。

---

# 16. 第十二步：把 workers.dev 加入 Turnstile Hostname Management

回到 Cloudflare：

```text
Turnstile
→ CleanC License Server
→ Settings
→ Hostname Management
```

添加你的 hostname，例如：

```text
cleanc-license-server.xxxxx.workers.dev
```

这里只填写 hostname，不要填写：

```text
https://
```

也不要加：

```text
/admin
```

正确：

```text
cleanc-license-server.xxxxx.workers.dev
```

错误：

```text
https://cleanc-license-server.xxxxx.workers.dev/admin
```

---

# 17. 第十三步：固定 BOOTSTRAP_BASE_URL

这是非常重要的一步。

Bootstrap 的作用是：

即使以后你把正式授权域名从：

```text
license.old-domain.com
```

换成：

```text
license.new-domain.com
```

客户端仍然可以通过固定的 workers.dev 地址查询当前正式 API 地址。

打开：

```text
wrangler.jsonc
```

找到：

```json
"BOOTSTRAP_BASE_URL": ""
```

填写刚才真实的 workers.dev 地址：

```json
"BOOTSTRAP_BASE_URL": "https://cleanc-license-server.xxxxx.workers.dev"
```

不要在最后加 `/`。

然后再次部署：

```bash
npm run deploy
```

此后 Bootstrap 地址固定为：

```text
https://cleanc-license-server.xxxxx.workers.dev/bootstrap/v1/config
```

建议 Windows 客户端永远内置这个 Bootstrap URL，而不是直接把未来的正式域名写死。

---

# 18. 第十四步：测试后台登录

打开：

```text
https://你的workers.dev/admin
```

输入：

- ADMIN_PASSWORD
- 完成 Turnstile

如果登录成功，会进入后台。

后台包含：

```text
仪表盘
授权管理
设备管理
操作日志
设置
```

---

# 19. 第十五步：创建第一个授权码

进入：

```text
授权管理
```

你可以选择：

## 永久

```text
permanent
```

永不过期，除非后台手工禁用。

## 激活后 N 天

例如：

```text
365
```

授权码未激活时不开始倒计时。

第一次成功绑定设备以后开始计算 365 天。

## 固定到期

选择：

```text
固定到期
```

网页会显示日期时间输入框。

例如：

```text
2027-12-31 23:59
```

## 设备数量

例如：

```text
1
```

表示只允许同时绑定一台设备。

## 批量生成

例如：

```text
100
```

系统随机生成 100 个：

```text
CLC-XXXX-XXXX-XXXX-XXXX
```

随机字符排除了容易看错的：

```text
0 O 1 I L
```

---

# 20. GitHub Actions 自动部署配置

本仓库已经包含：

```text
.github/workflows/deploy.yml
```

只要配置 GitHub Actions Secret，之后 push 到 `main` 就会自动：

```text
npm install
→ npm run typecheck
→ 检查 Cloudflare 配置
→ D1 migrations apply --remote
→ wrangler deploy
```

---

# 21. 创建 Cloudflare API Token

Cloudflare 控制台进入：

```text
My Profile / Account
→ API Tokens
→ Create Token
```

建议使用官方的：

```text
Edit Cloudflare Workers
```

模板，或创建 Custom Token。

至少需要满足当前项目执行 Worker 部署和 D1 Migration 所需要的权限。

限制 Resource 到你自己的 Cloudflare Account，权限不要无限放大。

生成 Token 后只显示一次，请复制保存。

不要把 Token 写进 GitHub 文件。

---

# 22. 找到 Cloudflare Account ID

在 Cloudflare Dashboard 中进入对应 Account。

可以在 Account Overview 或 Worker 页面找到：

```text
Account ID
```

格式类似：

```text
0123456789abcdef0123456789abcdef
```

---

# 23. 在 GitHub 添加 Actions Secrets

进入 GitHub 仓库：

```text
wwz554/CleanC-License-Server
```

打开：

```text
Settings
→ Secrets and variables
→ Actions
→ New repository secret
```

添加两个：

## Secret 1

名称：

```text
CLOUDFLARE_API_TOKEN
```

值：

```text
刚才 Cloudflare 创建的 API Token
```

## Secret 2

名称：

```text
CLOUDFLARE_ACCOUNT_ID
```

值：

```text
你的 Cloudflare Account ID
```

保存。

---

# 24. GitHub Actions 为什么会失败

当前 Actions 加了预检查。

如果没有配置完整，会直接给出明确错误。

## 错误：TODO_D1_DATABASE_ID

说明：

```text
wrangler.jsonc 还没填真实 D1 ID
```

## 错误：TODO_TURNSTILE_SITE_KEY

说明：

```text
wrangler.jsonc 还没填 Turnstile Site Key
```

## 错误：CLOUDFLARE_API_TOKEN 未配置

说明 GitHub：

```text
Settings
→ Secrets and variables
→ Actions
```

还没有添加 Token。

## 错误：CLOUDFLARE_ACCOUNT_ID 未配置

同理，添加 Account ID。

---

# 25. 手工运行 GitHub Actions

进入 GitHub：

```text
Actions
→ Deploy Cloudflare Worker
→ Run workflow
```

选择：

```text
main
```

点击：

```text
Run workflow
```

如果全部绿色，说明自动部署成功。

---

# 26. 以后绑定自己的域名

例如以后你有域名：

```text
example.com
```

希望使用：

```text
license.example.com
```

Cloudflare 当前推荐使用 Worker Custom Domain。

进入：

```text
Workers & Pages
→ cleanc-license-server
→ Settings
→ Domains & Routes
→ Add
→ Custom Domain
```

输入：

```text
license.example.com
```

Cloudflare 会自动处理对应 DNS 和证书。

注意：

- 域名必须属于你的 Cloudflare Zone；
- 如果这个 hostname 已经有冲突的 CNAME，需要先处理冲突；
- 不建议自己再另外建一个指向 workers.dev 的普通 CNAME 来替代 Worker Custom Domain。

---

# 27. 自定义域名绑定后必须做的第二件事

进入：

```text
Turnstile
→ 你的 Widget
→ Settings
→ Hostname Management
```

把：

```text
license.example.com
```

也添加进去。

最终 Turnstile Hostname 至少应该包含：

```text
cleanc-license-server.xxxxx.workers.dev
license.example.com
```

否则你从新域名访问 `/admin` 时，Turnstile 可能无法正常通过。

---

# 28. 在 CleanC 后台切换正式授权域名

等以下地址已经能正常访问：

```text
https://license.example.com/api/v1/health
```

再进入后台：

```text
/admin
→ 设置
```

填写：

```text
license.example.com
```

再次输入管理员密码并完成 Turnstile。

点击：

```text
检测并保存
```

服务端会先请求：

```text
https://license.example.com/api/v1/health
```

只有检测正常才会写入：

```text
PRIMARY_BASE_URL
```

以后：

```text
/bootstrap/v1/config
```

会告诉客户端新的主授权地址。

---

# 29. 为什么不要关闭 workers.dev

建议保留：

```text
cleanc-license-server.xxxxx.workers.dev
```

因为它承担稳定 Bootstrap 的作用。

正式业务 API 可以走：

```text
license.example.com
```

但客户端仍然可以把：

```text
https://cleanc-license-server.xxxxx.workers.dev/bootstrap/v1/config
```

作为永久发现地址。

如果正式域名以后失效或更换，只需要后台改变 `PRIMARY_BASE_URL`，客户端不用发新版软件改域名。

---

# 30. 恢复到 Bootstrap 地址

后台：

```text
设置
→ 恢复 Bootstrap 地址
```

需要：

- 管理员密码
- Turnstile

恢复后会删除 D1 中的：

```text
PRIMARY_BASE_URL
```

然后主授权 API 回到：

```text
BOOTSTRAP_BASE_URL
```

因此一定要完成 README 第 17 步，把 `BOOTSTRAP_BASE_URL` 固定为你的 workers.dev 地址。

---

# 31. Turnstile 安全说明

服务端会调用 Cloudflare 官方：

```text
https://challenges.cloudflare.com/turnstile/v0/siteverify
```

进行服务端验证。

不是只在网页前端显示一个验证码。

服务端还会检查 Turnstile 返回的：

```text
hostname
```

必须与当前访问后台的 hostname 相同。

因此：

- workers.dev 要加入 Hostname Management；
- 新自定义域名也要加入 Hostname Management。

本项目只允许当：

```text
TURNSTILE_SECRET=DISABLED
```

时跳过验证。

这个值只建议本机调试临时使用，正式环境不要设置为 DISABLED。

---

# 32. 管理员 Session 安全

登录成功后 Cookie 使用：

```text
HttpOnly
Secure
SameSite=Strict
```

Session 默认有效：

```text
8 小时
```

后台写操作额外要求 CSRF Token。

登录还带基础 IP 频率限制。

---

# 33. API 限流

当前主要限制：

```text
管理员登录：每 IP 每分钟最多 5 次
授权激活：每 IP 每分钟最多 10 次
validate/refresh：每 IP 每分钟最多 60 次
```

这是应用层基础限制。

如果正式用户量较大，后续还建议在 Cloudflare WAF / Rate Limiting Rules 再做一层边缘限流。

---

# 34. D1 数据表说明

## licenses

保存：

- 授权码
- 状态
- 授权类型
- 有效天数
- 到期时间
- 激活时间
- 最大设备数
- 备注

## devices

保存：

- 授权 ID
- deviceId
- 设备公钥
- Windows 版本
- App 版本
- 首次出现时间
- 最近在线时间
- 是否解绑

## audit_logs

记录：

- 管理员登录
- 登录失败
- 授权创建
- 批量授权创建
- 禁用 / 恢复
- 设备绑定
- 设备解绑
- 设备重新绑定
- 域名修改
- 域名恢复

## system_settings

当前主要保存：

```text
PRIMARY_BASE_URL
```

## domain_history

保存域名切换历史。

## device_challenges

保存设备 Challenge，默认 5 分钟失效，使用后不可重复验证。

## rate_limits

基础应用层限流计数。

---

# 35. Windows 客户端正确接入方式

建议客户端代码内只固定两个东西：

## 1. Bootstrap URL

```text
https://你的-workers.dev/bootstrap/v1/config
```

## 2. 服务端 P-256 公钥

即：

```text
cleanc-public.pem
```

客户端启动流程建议：

```text
1. 请求 Bootstrap
2. 使用内置服务端公钥验证 Bootstrap signature
3. 读取 canonicalBaseUrl
4. 使用 canonicalBaseUrl 调用授权 API
5. 服务端返回 Lease + signature
6. 客户端再次使用内置服务端公钥验证 Lease signature
7. 通过后才认为授权有效
```

不要仅仅依赖：

```text
HTTP 200
```

也不要只检查：

```text
success=true
```

客户端必须验证数字签名。

---

# 36. 设备公钥建议

每个 CleanC 客户端首次启动时生成自己的：

```text
P-256 私钥 / 公钥
```

设备私钥保存在本机安全位置。

激活时只上传：

```text
devicePublicKey
```

不要把设备私钥上传服务器。

服务器 Challenge：

```text
POST /api/v1/device/challenge
```

客户端使用本机私钥签名 nonce。

然后调用：

```text
POST /api/v1/device/verify
```

服务端使用之前保存的设备公钥验证签名。

---

# 37. 本地开发

如果只是在本机测试，可以执行：

```bash
npm run db:local
npm run dev
```

本地调试如果暂时没有 Turnstile，可在本地开发变量中临时使用：

```text
TURNSTILE_SECRET=DISABLED
```

但是正式 Cloudflare Worker **绝对不要**使用 DISABLED。

---

# 38. 常见故障排查

## 后台一直提示验证码错误

检查：

1. `TURNSTILE_SITE_KEY` 是否正确；
2. Cloudflare Secret `TURNSTILE_SECRET` 是否正确；
3. 当前 hostname 是否添加到 Turnstile Hostname Management；
4. Site Key 和 Secret Key 是否来自同一个 Turnstile Widget。

## GitHub Actions TypeScript Check 失败

先本机执行：

```bash
npm install
npm run typecheck
```

根据 TypeScript 报错处理。

## D1 Migration 失败

检查：

```text
wrangler.jsonc database_id
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

再执行：

```bash
npx wrangler d1 migrations list cleanc-license --remote
```

查看 Migration 状态。

## Worker 部署成功但后台 500

通常检查四个 Secret：

```text
ADMIN_PASSWORD
SESSION_SECRET
TURNSTILE_SECRET
LICENSE_SIGNING_PRIVATE_KEY
```

尤其是 `LICENSE_SIGNING_PRIVATE_KEY` 必须是 PKCS#8：

```text
-----BEGIN PRIVATE KEY-----
```

而不是：

```text
-----BEGIN EC PRIVATE KEY-----
```

如果你手里是 EC PRIVATE KEY，按第 11 步转换成 PKCS#8。

## 保存新域名提示 DOMAIN_NOT_READY

先直接浏览器测试：

```text
https://新域名/api/v1/health
```

必须返回：

```json
{
  "status": "ok",
  "apiVersion": 1
}
```

如果打不开，说明 Custom Domain 还没真正绑定完成。

## 固定到期授权创建失败

固定到期时间必须：

- 是有效时间；
- 晚于当前时间。

## DEVICE_NOT_BOUND

说明客户端直接调用了 validate/refresh，但是设备没有完成 activate。

先调用：

```text
/api/v1/license/activate
```

## DEVICE_LIMIT_REACHED

授权码已经绑定达到最大设备数。

后台进入：

```text
设备管理
```

解绑旧设备，或新建允许更多设备的授权。

---

# 39. 正式上线前检查清单

逐项确认：

```text
[ ] D1 已创建
[ ] wrangler.jsonc 已填写真实 database_id
[ ] Turnstile Widget 已创建
[ ] wrangler.jsonc 已填写真实 Site Key
[ ] ADMIN_PASSWORD 已保存为 Cloudflare Secret
[ ] SESSION_SECRET 已保存为 Cloudflare Secret
[ ] TURNSTILE_SECRET 已保存为 Cloudflare Secret
[ ] LICENSE_SIGNING_PRIVATE_KEY 已保存为 Cloudflare Secret
[ ] cleanc-public.pem 已保存到 Windows 客户端
[ ] D1 Migration 已执行
[ ] Worker 已首次部署
[ ] /api/v1/health 正常
[ ] /admin 能打开
[ ] workers.dev 已加入 Turnstile Hostname Management
[ ] BOOTSTRAP_BASE_URL 已固定为 workers.dev
[ ] GitHub CLOUDFLARE_API_TOKEN 已配置
[ ] GitHub CLOUDFLARE_ACCOUNT_ID 已配置
[ ] GitHub Actions 能完整跑通
[ ] 创建测试授权成功
[ ] 测试设备 activate 成功
[ ] validate 成功
[ ] refresh 成功
[ ] 禁用授权后客户端无法继续刷新授权
[ ] 解绑设备后 DEVICE_NOT_BOUND 生效
[ ] 原设备重新 activate 可以重新绑定
[ ] Bootstrap signature 客户端验证成功
[ ] Lease signature 客户端验证成功
```

---

# 40. 关于“防破解”

任何运行在用户自己电脑上的软件都不能做到绝对不可破解。

这个方案重点提高破解成本：

```text
服务器端决定授权状态
+ 短期 Lease
+ P-256 数字签名
+ 设备绑定
+ Challenge / Verify
+ Bootstrap 动态服务地址
+ 后台 Turnstile
+ 管理端 CSRF
+ 审计日志
```

Windows 客户端还应该同时做：

- 不在本地明文保存“永久已授权=true”；
- 每次使用缓存 Lease 都验证服务端签名；
- Lease 到期必须重新从服务器刷新；
- 关键功能不要只由一个布尔变量控制；
- 对授权校验代码做合理混淆和完整性校验；
- 服务端公钥可以公开，但必须防止客户端代码被简单替换公钥后绕过验证。

---

# 41. 重要安全原则

永远不要提交以下内容到 GitHub：

```text
真实管理员密码
SESSION_SECRET
TURNSTILE_SECRET
LICENSE_SIGNING_PRIVATE_KEY
CLOUDFLARE_API_TOKEN
设备私钥
```

可以提交：

```text
TURNSTILE_SITE_KEY
D1 database_id
CleanC 服务端公钥
Workers.dev URL
自定义 API 域名
```

---

# 42. 推荐最终架构

```text
CleanC Windows 客户端
        │
        │ 固定 Bootstrap URL
        ▼
xxxx.workers.dev/bootstrap/v1/config
        │
        │ P-256 签名返回 canonicalBaseUrl
        ▼
license.yourdomain.com
        │
        ├── /api/v1/license/activate
        ├── /api/v1/license/validate
        ├── /api/v1/license/refresh
        ├── /api/v1/device/challenge
        └── /api/v1/device/verify
        │
        ▼
Cloudflare Worker
        │
        ├── Cloudflare D1
        ├── Turnstile Siteverify
        └── P-256 License Signing Private Key
```

管理后台：

```text
https://license.yourdomain.com/admin
```

或者保留：

```text
https://xxxx.workers.dev/admin
```

---

# 43. Cloudflare 官方参考文档

Workers Custom Domains：

```text
https://developers.cloudflare.com/workers/configuration/routing/custom-domains/
```

Workers GitHub Actions：

```text
https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/
```

D1 Wrangler Commands：

```text
https://developers.cloudflare.com/d1/wrangler-commands/
```

Turnstile Hostname Management：

```text
https://developers.cloudflare.com/turnstile/additional-configuration/hostname-management/
```

Turnstile Server-side Validation：

```text
https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
```

---

# 44. 当前部署状态说明

如果仓库还是刚初始化的状态，`wrangler.jsonc` 默认仍可能包含：

```text
TODO_D1_DATABASE_ID
TODO_TURNSTILE_SITE_KEY
```

并且 GitHub Actions 还需要：

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

这些值没配置以前，Actions **故意不会继续正式部署**。

这样可以避免：

- 部署到错误 Cloudflare 账号；
- Worker 绑定错误数据库；
- Turnstile 无法登录；
- 使用未配置的安全参数上线。

把本 README 对应步骤全部完成后，再运行 GitHub Actions 即可。
