# CleanC License Server

CleanC License Server 是 CleanC Windows 客户端的生产授权服务，基于：

- Cloudflare Pages
- Pages Functions
- Cloudflare D1
- Cloudflare Turnstile
- P-256 / ECDSA 设备身份与服务器签名
- GitHub 直连 Cloudflare Pages 自动部署

当前生产授权规则已经固定为：

1. **一个授权码同一时间只能绑定 1 台设备。**
2. **一台设备同一时间只能绑定 1 个有效授权。**
3. 同一个授权码并发激活时，**第一个成功拿到 D1 激活锁的请求成功**，其他请求失败。
4. 管理员后台手动“解绑设备”后，该授权码可以重新绑定另一台设备。
5. “激活后 N 天”授权从**第一次成功激活**开始计时；创建后一直没人使用，不会提前消耗天数。
6. 72 小时 Lease 只是客户端离线租约周期，不改变 7 天、30 天等授权总有效期。
7. Lease 有效期间客户端本地验证服务器签名，不需要每次启动都访问服务器。
8. Lease 快到期时，只需要 **challenge + refresh 两次请求**。
9. 授权总有效期到期后，客户端立即停止使用；设备联网后用设备私钥完成一次到期上报，服务器释放旧绑定。
10. 旧绑定释放后，该设备可以输入新的授权码；如果管理员已经给原授权码续期，也可以重新使用原授权码。

> 本仓库是公开仓库。管理员密码、Turnstile Secret、服务器签名私钥等敏感值绝对不要提交到 GitHub。

---

# 一、项目结构

```text
CleanC-License-Server/
├─ functions/
│  ├─ index.ts
│  └─ [[path]].ts
├─ public/
│  ├─ index.html
│  └─ _routes.json
├─ src/
│  ├─ admin.ts
│  ├─ worker.ts
│  ├─ pages.ts
│  └─ webcrypto-compat.d.ts
├─ .github/workflows/ci.yml
├─ .env.example
├─ package.json
├─ tsconfig.json
└─ README.md
```

`src/pages.ts` 是当前生产 Pages 适配层，负责：

- D1 自动建表和自动升级；
- 单授权单设备约束；
- 单设备单授权约束；
- 并发激活锁；
- 72 小时 Lease 两步续期；
- 到期设备自动释放；
- duration 授权续期；
- 生产配置检查。

`src/worker.ts` 保留基础授权和管理后台核心逻辑。

---

# 二、部署方式

部署方式是：

```text
GitHub main
   ↓ push
Cloudflare Pages Git Integration
   ↓
npm install
   ↓
npm run build
   ↓
Cloudflare Pages 自动发布
```

`.github/workflows/ci.yml` **不负责部署 Cloudflare**。

它只做代码检查：

```text
npm install
npm run build
TypeScript check
```

所以：

- 不需要 GitHub Cloudflare API Token；
- 不需要 GitHub Actions 部署；
- Cloudflare Pages 直接拉取 GitHub；
- GitHub CI 只负责阻止明显的 TypeScript 错误进入生产。

---

# 三、Cloudflare Pages 连接 GitHub

Cloudflare 控制台进入：

```text
Workers & Pages
→ Create application
→ Pages
→ Connect to Git / Import existing Git repository
```

选择：

```text
wwz554/CleanC-License-Server
```

设置：

| 项目 | 内容 |
|---|---|
| Production branch | `main` |
| Framework preset | `None` |
| Build command | `npm run build` |
| Build output directory | `public` |
| Root directory | 留空 |

然后点击：

```text
Save and Deploy
```

第一次没有绑定 D1 时接口返回 `D1_BINDING_MISSING` 属于正常现象。

---

# 四、创建并绑定 D1

Cloudflare 控制台：

```text
Storage & Databases
→ D1 SQL Database
→ Create database
```

建议数据库名：

```text
cleanc-license
```

然后回到 Pages 项目：

```text
Settings
→ Bindings
→ Add
→ D1 database
```

变量名必须填写：

```text
DB
```

选择刚创建的数据库。

绑定后重新部署一次 Production。

## 不需要手工建表

第一次正常请求到达 Pages Functions 后，代码会自动创建/升级：

```text
licenses
devices
audit_logs
system_settings
domain_history
device_challenges
rate_limits
activation_locks
```

同时自动创建索引和数据库 Trigger。

代码使用 `CREATE TABLE IF NOT EXISTS`、`CREATE INDEX IF NOT EXISTS` 和版本号升级，因此重新部署不会清空已有数据。

---

# 五、生产数据库保护规则

数据库层不是只相信前端和 TypeScript，而是额外锁死关键授权规则。

当前 D1 会保证：

```text
一个 license_id 只能有 1 条 revoked_at IS NULL 的设备记录
一个 device_id 只能有 1 条 revoked_at IS NULL 的授权记录
max_devices 永远只能是 1
```

因此即使以后前端被篡改，提交：

```json
{"maxDevices":1000}
```

服务端也会强制归一化为 1，数据库也会拒绝大于 1 的配置。

如果从旧测试数据库升级，发现历史上同一个授权码或同一个设备存在多条活动绑定，升级逻辑会保留最早的有效绑定，并自动把其他记录标记为已解绑，然后再创建唯一索引。

---

# 六、授权类型

## 1. 永久授权

```text
license_type = permanent
expires_at = NULL
```

不会因为时间自动失效，但仍受管理员禁用、设备解绑和 72 小时 Lease 规则控制。

## 2. 激活后 N 天

例如创建 7 天授权：

```text
license_type = duration
duration_days = 7
activated_at = NULL
expires_at = NULL
```

创建日期不参与计时。

例如 2026-09-17 创建，直到 2027-01-01 才第一次使用：

```text
2026-09-17 创建
↓
一直未激活
↓
仍然完整保留 7 天
↓
2027-01-01 10:00 首次成功激活
↓
activated_at = 2027-01-01 10:00
expires_at   = 2027-01-08 10:00
```

之后：

- 重启软件不会重置时间；
- 72 小时续租不会重置时间；
- 第二次激活不会重新计算 7 天；
- 管理员禁用再恢复不会暂停倒计时；
- 管理员解绑不会把授权恢复成“未使用”。

## 3. 固定到期时间

创建时直接指定绝对到期时间。

无论什么时候第一次使用，到这个时间都会失效。

---

# 七、创建 Turnstile

Cloudflare：

```text
Turnstile
→ Add widget
```

Hostname Management 先加入 Pages 域名，例如：

```text
cleanc-license-server.pages.dev
```

绑定正式域名后，再把正式域名加入 Hostname Management。

保存：

- Site Key
- Secret Key

Site Key 是公开值。
Secret Key 必须作为加密 Secret。

---

# 八、Pages Variables and Secrets

进入：

```text
Workers & Pages
→ CleanC 项目
→ Settings
→ Variables and Secrets
```

## 普通变量

```text
APP_NAME=CleanC
TURNSTILE_SITE_KEY=你的 Turnstile Site Key
LEASE_HOURS=72
BOOTSTRAP_BASE_URL=https://你的项目.pages.dev
```

`BOOTSTRAP_BASE_URL` 建议永远保留 Pages 自带地址，作为客户端固定入口。

## 加密 Secret

必须配置：

```text
ADMIN_PASSWORD
SESSION_SECRET
TURNSTILE_SECRET
LICENSE_SIGNING_PRIVATE_KEY
```

### SESSION_SECRET

建议：

```bash
openssl rand -base64 48
```

### DEVICE_PROOF_SECRET

**当前生产协议已经不再需要。**

旧版三步续租使用过 `DEVICE_PROOF_SECRET`，现在设备签名直接在 `refresh` 中验证，所以不再需要单独的 Device Proof。

---

# 九、生成服务器 P-256 签名密钥

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ec-private-sec1.pem
openssl pkcs8 -topk8 -nocrypt -in ec-private-sec1.pem -out cleanc-private.pem
openssl pkey -in cleanc-private.pem -pubout -out cleanc-public.pem
```

得到：

```text
cleanc-private.pem
cleanc-public.pem
```

## 私钥

完整放入 Cloudflare 加密 Secret：

```text
LICENSE_SIGNING_PRIVATE_KEY
```

绝对不能上传 GitHub。

## 公钥

嵌入 CleanC Windows 客户端。

客户端使用公钥验证服务器返回的：

```text
signedPayload
signature
```

---

# 十、首次激活流程

推荐客户端流程：

```text
启动 CleanC
↓
本地没有有效授权
↓
GET /bootstrap/v1/config
↓
客户端使用内置服务器公钥验证 Bootstrap 签名
↓
取得 canonicalBaseUrl
↓
本机生成 P-256 设备密钥对
↓
私钥只保存在本机安全存储
↓
POST /api/v1/license/activate
↓
提交：
licenseKey
deviceId
devicePublicKey
deviceName
windowsVersion
appVersion
↓
服务器竞争激活锁
↓
成功者绑定设备
↓
返回签名 Lease
```

## 并发激活

例如同一个授权码同时被三台电脑提交：

```text
A ─┐
B ─┼→ 同一个授权码
C ─┘
```

服务器使用 D1 锁：

```text
license:<licenseKey>
```

只有第一个成功取得锁的请求进入绑定流程。

其他并发请求直接返回：

```text
ACTIVATION_BUSY
```

第一个设备完成绑定后，之后其他设备再提交同一个授权码会返回：

```text
LICENSE_ALREADY_BOUND
```

必须由管理员后台先解绑，才能换机。

---

# 十一、同一设备不能同时占两个授权

服务器同时对设备使用：

```text
device:<deviceId>
```

激活锁。

数据库还有：

```text
uq_one_active_license_per_device
```

唯一索引。

因此：

```text
设备 A + 授权码 1 = 已绑定
```

在授权码 1 的绑定没有释放之前，设备 A 不能再直接绑定授权码 2。

这样可以防止同一设备同时占用多个有效授权。

---

# 十二、72 小时 Lease

默认：

```text
LEASE_HOURS=72
```

首次激活成功后服务器返回签名 Lease。

Lease 中包含：

```text
version
licenseId
deviceId
edition
features
issuedAt
serverTime
expiresAt
licenseExpiresAt
leaseHours
renewalProtocol
nonce
```

其中：

```text
expiresAt
```

是本次离线 Lease 到期时间。

```text
licenseExpiresAt
```

是授权总有效期。

服务器实际使用：

```text
Lease 到期时间 = min(当前时间 + 72 小时, 授权总到期时间)
```

所以一个只剩 10 小时的 7 天授权，不会再拿到完整 72 小时 Lease，而只会拿到最多 10 小时。

---

# 十三、客户端倒计时和时间戳

客户端左下角倒计时应该使用服务器签名数据里的：

```text
licenseExpiresAt
```

而不是客户端自己生成一个普通时间戳。

必须先验证：

```text
signedPayload + signature
```

验证成功后才能信任里面的到期时间。

建议客户端本地同时保存：

```text
serverTime
licenseExpiresAt
最近一次可信服务器时间
本机单调时钟基准
```

正常运行时优先用单调计时器计算经过时间，避免用户简单修改 Windows 系统时间把倒计时拨回去。

如果检测到本机系统时间明显回退到最近一次可信服务器时间之前，应拒绝继续延长本地有效期，等下次联网校准。

---

# 十四、72 小时续期：只需要两次请求

旧版：

```text
challenge
verify
deviceProof
refresh
```

已经废弃。

当前生产流程只有：

```text
① POST /api/v1/device/challenge
↓
服务器返回一次性 nonce
↓
客户端用本机 P-256 私钥签 nonce
↓
② POST /api/v1/license/refresh
   licenseKey
   deviceId
   nonce
   signature
↓
服务器验证设备公钥
↓
nonce 标记已使用
↓
返回新的签名 Lease
```

正常情况下，每 72 小时只有这两次很小的网络请求。

客户端在 Lease 仍有效时，不需要：

- 每次启动验证服务器；
- 定时每几分钟访问服务器；
- 每次清理 C 盘都认证；
- 单独调用 `device/verify`。

---

# 十五、废弃接口

生产客户端不要再使用：

```text
POST /api/v1/license/validate
POST /api/v1/device/verify
```

它们现在会返回：

```text
410 ENDPOINT_DEPRECATED
```

目的就是避免客户端继续走旧的高频/三步认证流程。

---

# 十六、授权总时间到期后的处理

例如：

```text
7 天授权
licenseExpiresAt = 2026-09-24 18:00
```

到达该时间后：

```text
客户端倒计时 = 0
↓
立即停止 CleanC 受授权保护的功能
↓
不得因为当前 Lease 原本还有时间而继续运行
```

因为服务器签发 Lease 时已经使用：

```text
min(72 小时, licenseExpiresAt)
```

所以正常实现下 Lease 本身也不会超过授权总到期时间。

## 设备联网后的到期上报

到期后客户端仍然可以调用：

```text
POST /api/v1/device/challenge
```

服务器会给当前已绑定设备一个 nonce，即使该授权总时间已经到期。

客户端私钥签名后调用：

```text
POST /api/v1/license/refresh
```

服务器验证：

1. 授权码；
2. deviceId；
3. 当前活动绑定；
4. nonce；
5. P-256 设备签名。

验证通过后发现授权已经到期，会：

```text
把该 devices 记录 revoked_at 写入当前时间
```

并返回：

```text
LICENSE_EXPIRED_RELEASED
```

同时告诉客户端：

```text
deviceReleased = true
canActivateNewLicense = true
```

这一步的作用是：**由原来真正绑定的设备自己证明身份并释放旧授权占用。**

攻击者只知道 licenseKey + deviceId，没有对应设备私钥，不能伪造这个到期释放过程。

---

# 十七、到期后输入新授权码

旧绑定完成释放后：

```text
设备 A
旧授权：已到期 + 已释放
↓
输入新的授权码 B
↓
POST /api/v1/license/activate
↓
设备 A 可以绑定授权 B
```

新的授权同样开始自己的授权生命周期。

---

# 十八、原授权码续期

管理后台对于：

```text
license_type = duration
```

的授权提供“续期”操作。

管理员可以输入：

```text
续期 N 天
```

服务器计算：

```text
基准时间 = max(当前时间, 原 expires_at)
新 expires_at = 基准时间 + N 天
```

所以：

- 没过期就从原到期时间继续往后加；
- 已经过期则从当前时间重新往后加；
- 不修改第一次 `activated_at`；
- 不把授权伪装成“从未激活”。

如果管理员在设备上报到期**之前**已经续期：

```text
challenge + refresh
```

会直接得到新的 Lease，设备绑定继续保留。

如果设备已经完成到期上报并释放绑定，管理员之后再续期：

```text
用户重新输入原授权码
→ activate
→ 原授权重新绑定该设备
```

---

# 十九、管理员手动解绑

后台设备管理中可以点击：

```text
解绑
```

解绑以后：

- 当前设备不再占用这个授权码；
- 这个授权码可以绑定另一台设备；
- 原设备也可以改用另一个授权码。

管理员解绑属于人工换机操作，与自然到期释放是两条独立流程。

---

# 二十、管理员创建授权

管理后台已经删除“设备数量”设置。

创建授权只需要选择：

```text
自定义授权码 / 随机授权码
授权类型
有效天数或固定到期时间
生成数量
备注
```

服务器无论收到什么 `maxDevices`，都会强制：

```text
max_devices = 1
```

---

# 二十一、主要 API

## 公共/客户端

```text
GET  /api/v1/health
GET  /api/v1/meta
GET  /bootstrap/v1/config
POST /api/v1/license/activate
POST /api/v1/device/challenge
POST /api/v1/license/refresh
```

## 已废弃

```text
POST /api/v1/license/validate
POST /api/v1/device/verify
```

## 管理后台

```text
/admin
/admin/api/...
```

其中 duration 授权续期：

```text
POST /admin/api/licenses/{licenseId}/renew
```

---

# 二十二、生产验证

部署后依次检查：

## Health

```text
https://你的项目.pages.dev/api/v1/health
```

应该返回：

```json
{
  "status": "ok",
  "service": "cleanc-license-server",
  "apiVersion": 2
}
```

## Bootstrap

```text
https://你的项目.pages.dev/bootstrap/v1/config
```

应该包含：

```text
canonicalBaseUrl
issuedAt
signedPayload
signature
```

## Admin

```text
https://你的项目.pages.dev/admin
```

登录必须经过：

```text
管理员密码 + Turnstile
```

## D1

第一次正常访问后应看到：

```text
licenses
devices
audit_logs
system_settings
domain_history
device_challenges
rate_limits
activation_locks
```

---

# 二十三、正式域名

Pages 自带地址建议一直保留作为 Bootstrap：

```text
https://xxxxx.pages.dev
```

正式授权域名例如：

```text
https://license.example.com
```

在 Pages Custom domains 绑定后：

1. 测试 `/api/v1/health`；
2. 把正式域名加入 Turnstile Hostname Management；
3. 登录 `/admin`；
4. 在设置中保存新的主授权域名。

客户端以后通过签名 Bootstrap 获得最新：

```text
canonicalBaseUrl
```

---

# 二十四、生产上线检查表

上线前确认：

```text
[ ] Cloudflare Pages 已连接 GitHub main
[ ] Build command = npm run build
[ ] Build output = public
[ ] D1 已绑定为 DB
[ ] TURNSTILE_SITE_KEY 已设置
[ ] TURNSTILE_SECRET 已加密设置
[ ] ADMIN_PASSWORD 已加密设置
[ ] SESSION_SECRET 已加密设置
[ ] LICENSE_SIGNING_PRIVATE_KEY 已加密设置
[ ] LEASE_HOURS = 72
[ ] BOOTSTRAP_BASE_URL 指向稳定 pages.dev 地址
[ ] Windows 客户端内置服务器公钥
[ ] 客户端私钥只保存在本机安全存储
[ ] 客户端验证 signedPayload/signature 后才信任时间
[ ] 客户端倒计时使用 licenseExpiresAt
[ ] 客户端不允许通过回拨系统时间延长授权
[ ] Lease 有效时不进行高频在线认证
[ ] Lease 到期前使用 challenge + refresh
[ ] 授权总时间到 0 立即停止使用
[ ] 到期联网后完成 LICENSE_EXPIRED_RELEASED
[ ] 新授权激活前确保旧活动绑定已释放
```

完成以上项目后，即为当前 CleanC License Server 的生产授权模型。
