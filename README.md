# CleanC License Server

Cloudflare Workers + D1 + Turnstile 的 CleanC 授权服务。实现管理员后台、授权码、设备绑定、Lease 签名、动态主域名、Bootstrap 自动发现、操作日志与基础安全策略。

## 已实现

- `/admin` Apple-inspired Liquid Glass 管理后台
- 管理员密码 + Cloudflare Turnstile 登录
- HttpOnly / Secure / SameSite=Strict Session
- CSRF 防护与基础 D1 限流
- 单个/批量授权码（最多 1000）
- 自定义授权码、有效期、设备上限、禁用/恢复、软删除
- 设备绑定、解绑/吊销
- `POST /api/v1/license/activate`
- `POST /api/v1/license/validate`
- `POST /api/v1/license/refresh`
- `POST /api/v1/device/challenge`
- `POST /api/v1/device/verify`
- `GET /bootstrap/v1/config`（ES256 数字签名）
- `GET /api/v1/health` / `GET /api/v1/meta`
- D1 操作审计、域名历史
- `PRIMARY_BASE_URL` 存 D1，不写死正式域名
- GitHub Actions 自动迁移 + 部署

## 第一次部署

### 1. 安装依赖

```bash
npm install
```

### 2. 创建 D1

```bash
npx wrangler login
npx wrangler d1 create cleanc-license
```

把输出的 `database_id` 写入 `wrangler.jsonc` 的 `TODO_D1_DATABASE_ID`。

### 3. 创建 Turnstile

在 Cloudflare Dashboard 创建 Turnstile Widget，把 Site Key 写到 `wrangler.jsonc` 的 `TODO_TURNSTILE_SITE_KEY`。

### 4. 生成签名密钥

CleanC Server 使用 P-256 / ES256。浏览器控制台或 Node 22 可生成 JWK。推荐使用下面脚本：

```js
const { subtle } = crypto;
const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
console.log('PRIVATE=', JSON.stringify(await subtle.exportKey('jwk', kp.privateKey)));
console.log('PUBLIC=', JSON.stringify(await subtle.exportKey('jwk', kp.publicKey)));
```

`PRIVATE` 只放 Cloudflare Secret，`PUBLIC` 放进 CleanC 客户端用于验证 Bootstrap 与 Lease。

### 5. 配置 Secrets

```bash
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put SESSION_SECRET
npx wrangler secret put TURNSTILE_SECRET
npx wrangler secret put LICENSE_SIGNING_PRIVATE_KEY
```

**绝对不要把真实密码、Turnstile Secret 或签名私钥提交到 GitHub。**

### 6. 初始化数据库并部署

```bash
npm run db:remote
npm run deploy
```

部署成功后访问：

```text
https://<worker-name>.<subdomain>.workers.dev/admin
```

## GitHub Actions 自动部署

仓库 Settings → Secrets and variables → Actions 添加：

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

Worker 自身的 4 个 Secret 仍建议用 `wrangler secret put` 设置在 Cloudflare，GitHub 不需要持有它们。

> 注意：自动部署前必须先把 `wrangler.jsonc` 中 D1 `database_id` 和 Turnstile Site Key 替换为真实值。

## 自定义域名

1. Cloudflare → Workers & Pages → `cleanc-license-server` → Settings → Domains & Routes → Add Custom Domain。
2. Turnstile → Hostname Management 添加新域名。
3. 用新域名打开 `/admin`。
4. 设置 → 域名与 API → 设置正式域名。
5. 系统将 `PRIMARY_BASE_URL` 写入 D1，Bootstrap 和后台完整 API 地址立即切换，不需要重新编译 CleanC。

## Bootstrap

客户端永久保存 workers.dev：

```text
GET https://<worker>.workers.dev/bootstrap/v1/config
```

返回的 `payload` 包含 `canonicalBaseUrl`、`issuedAt` 和 `apiVersion`，`signature` 为 ES256。客户端必须用内置 Server Public Key 验证后才接受新的主授权地址。

## 管理员密码

实际管理员密码不在仓库中。请只通过：

```bash
npx wrangler secret put ADMIN_PASSWORD
```

写入 Cloudflare Secret。
