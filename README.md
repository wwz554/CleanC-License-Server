# CleanC License Server

CleanC License Server 是 CleanC Windows 客户端使用的生产授权服务，基于：

```text
Cloudflare Pages
+ Pages Functions
+ D1
+ Turnstile
```

当前生产协议：

```text
API Version: 3
Lease Version: 4
默认 Lease: 72 小时
续期: challenge + refresh
一个授权码: 同一时间最多 1 台设备
一台设备: 同一时间最多 1 个活动授权
```

## 文档

从零部署请直接阅读：

**[安装部署教程.md](./安装部署教程.md)**

正式给客户使用之前，请逐项执行：

**[生产上线验收清单.md](./生产上线验收清单.md)**

安装教程已经按 Cloudflare Pages 直接连接 GitHub 的方式写好，从创建 Pages、绑定 D1、创建 Turnstile、填写 Variables/Secrets、生成 P-256 密钥到生产验证都有简体中文说明和填写实例。

---

# 当前生产授权逻辑

## 永久授权

服务器签名 Lease 明确返回：

```text
licenseType = permanent
isPermanent = true
licenseExpiresAt = null
displayText = 永久授权
countdownRequired = false
```

Windows 客户端右下角只显示：

```text
永久授权
```

`expiresAt` 仍然表示默认 72 小时的内部 Lease，到期前客户端静默续租；它不是永久授权的总到期时间。

## 激活后 N 天

例如 7 天授权：

```text
创建后无人激活 → 不开始计时
第一次成功激活 → activated_at = 当前服务器时间
expires_at = activated_at + 7 天
```

管理员解绑、重新绑定、换电脑都不会重新计算首次激活时间。

## 固定到期

固定到期授权在创建时就具有绝对到期时间，到达该时间即失效，与首次激活时间无关。

---

# 设备绑定规则

数据库和服务端同时限制：

```text
一个授权码只能有 1 个活动设备
一个设备只能有 1 个活动授权
```

并发激活使用 D1 锁：

```text
license:<licenseKey>
device:<deviceId>
```

第一个成功取得锁的请求进入绑定流程，其他并发请求失败。

管理员可以在后台手动解绑。解绑以后：

```text
授权码可以绑定另一台设备
原设备可以绑定其他授权码
```

生产激活还采用：

```text
公网 IP 宽松总限流
+
单设备细粒度限流
```

这样公司、校园网、运营商 NAT 等共享公网 IP 的正常客户不会因为共用出口地址轻易互相误伤。

---

# 72 小时续期

正常情况下客户端无需频繁联网。

Lease 有效期间只在本地验证服务器签名。

快到期时执行：

```text
POST /api/v1/device/challenge
↓
客户端设备 P-256 私钥签 nonce
↓
POST /api/v1/license/refresh
↓
服务器验证设备签名
↓
签发新的 Lease
```

旧接口：

```text
POST /api/v1/license/validate
POST /api/v1/device/verify
```

已经废弃，生产客户端不要使用。

续租限流同样按“公网 IP 宽松总限流 + 单设备细限流”处理，降低共享 NAT 环境误伤。

---

# 授权总时间到期

时长/固定授权到达 `licenseExpiresAt` 后，客户端应立即停止受授权保护功能。

设备联网后执行：

```text
challenge + refresh
```

服务器验证设备私钥以后，再次读取并原子确认授权仍然过期，然后才释放旧绑定并返回：

```text
LICENSE_EXPIRED_RELEASED
```

这样可以避免设备刚到期上报时管理员恰好续期，服务端仍按旧状态误解绑客户。

之后设备可以激活新的授权码。

如果管理员已经给原时长授权续期，则原设备可以继续刷新；如果旧绑定已经释放，则重新激活原授权码即可。

管理员给 duration 授权“续期”只延长到期时间；如果该授权之前是 `disabled`，续期不会自动恢复为 `active`，必须由管理员明确点击“恢复”。

---

# 主要客户端 API

```text
GET  /api/v1/health
GET  /api/v1/meta
GET  /bootstrap/v1/config
POST /api/v1/license/activate
POST /api/v1/device/challenge
POST /api/v1/license/refresh
```

生产 health 应返回：

```json
{
  "status": "ok",
  "service": "cleanc-license-server",
  "apiVersion": 3,
  "leaseVersion": 4,
  "renewalProtocol": "challenge-refresh",
  "singleDeviceLicense": true
}
```

---

# Cloudflare Pages 构建参数

```text
Production branch: main
Framework preset: None
Build command: npm run build
Build output directory: public
Root directory: 留空
```

D1 Binding 变量名必须是：

```text
DB
```

---

# 生产变量

普通变量：

```text
APP_NAME=CleanC
TURNSTILE_SITE_KEY=你的SiteKey
LEASE_HOURS=72
BOOTSTRAP_BASE_URL=https://你的项目.pages.dev
```

加密 Secret：

```text
ADMIN_PASSWORD
SESSION_SECRET
TURNSTILE_SECRET
LICENSE_SIGNING_PRIVATE_KEY
```

`DEVICE_PROOF_SECRET` 已不再是当前生产协议必需项。

完整填写示例请看：

**[安装部署教程.md](./安装部署教程.md)**

---

# 项目结构

```text
CleanC-License-Server/
├─ functions/
│  ├─ index.ts
│  └─ [[path]].ts
├─ public/
│  ├─ index.html
│  └─ _routes.json
├─ src/
│  ├─ router.ts
│  ├─ activation.ts
│  ├─ production.ts
│  ├─ pages.ts
│  ├─ worker.ts
│  ├─ admin.ts
│  └─ webcrypto-compat.d.ts
├─ .github/workflows/ci.yml
├─ .env.example
├─ package.json
├─ tsconfig.json
├─ README.md
├─ 安装部署教程.md
└─ 生产上线验收清单.md
```

各层职责：

```text
functions/*
  ↓
src/router.ts
  ↓
生产激活 → src/activation.ts
生产 Bootstrap / health / meta / challenge / refresh → src/production.ts
数据库初始化、后台兼容层 → src/pages.ts
基础后台与历史兼容核心 → src/worker.ts
```

`src/router.ts` 是 Cloudflare Pages 对外请求的最外层生产路由，负责初始化重试、NAT 友好限流、生产激活分流，以及数据库额外安全保护。

`src/activation.ts` 专门处理生产首次激活、设备/授权双锁、单设备绑定、首次计时和生产 Lease 签发。

`src/production.ts` 负责外部 API v3 / Lease v4、Bootstrap 签名、两步续期、到期安全释放和生产数据库热修。

`src/pages.ts` 负责 D1 自动初始化、历史数据库兼容升级和管理 API 包装。

`src/worker.ts` 中仍保留部分 API v2 / 旧 Device Proof 兼容代码，但它不是 Pages 对外入口。外部生产请求全部先经过 `functions/* → router.ts`，生产客户端只能使用本文列出的 API v3 流程。

---

# 安全提醒

本仓库如果是公开仓库，绝对不要提交：

```text
管理员真实密码
SESSION_SECRET
Turnstile Secret
服务器 P-256 私钥
Cloudflare API Token
```

服务器私钥只能保存在 Cloudflare 加密 Secret 中。

Windows 客户端只内置服务器公钥。

每次 main 分支更新后，GitHub `Code Check` 会执行依赖安装和 TypeScript 检查；Cloudflare Pages Git Integration 负责真正生产部署。
