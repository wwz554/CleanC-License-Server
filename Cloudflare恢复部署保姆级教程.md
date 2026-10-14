# 授权服务器恢复部署保姆级教程

适用：本次交付的 CleanC + 网工拼音授权服务。服务器地址是 **https://wwz554.ccwu.cc**，Cloudflare Pages 项目是 **cleanc-license-server**，数据库是 **cleanc-license**，GitHub 仓库是 **wwz554/CleanC-License-Server**。API v3、Lease v4、challenge + refresh。

## 1. 先认识这个源码文件夹

| 内容 | 用途 |
|---|---|
| `src`、`functions`、`public` | 完整服务器源码和页面 |
| `package.json`、两个lock文件 | 固定版本依赖 |
| `wrangler.toml` | 当前项目、公开Turnstile Site Key、DB绑定配置 |
| `private-secrets/LICENSE_SIGNING_PRIVATE_KEY.pem` | 原P-256签名私钥，CleanC和网工拼音客户端验签所对应的钥匙 |
| `private-secrets/OFFLINE_RSA_PRIVATE_KEY.pem` | 原CleanC旧版离线二维码RSA私钥 |
| `private-secrets/ADMIN_PASSWORD.txt` | 原管理员密码 |
| `private-secrets/SESSION_SECRET.txt` | 原后台Session/CSRF Secret |
| `private-secrets/TURNSTILE_SECRET.txt` | 原Turnstile Secret |
| `private-secrets/cloudflare-secrets.json` | 上面五项的准确原值，可批量恢复 |
| `private-secrets/database-before-upgrade.sql` | 升级前数据库副本 |
| `private-secrets/database-after-upgrade.sql` | 升级后数据库副本，包含产品区分、授权码与设备绑定 |
| `server-public.pem`、`offline-public.pem` | 与原私钥配套的公钥，用于核对恢复材料 |
| `恢复材料清单.json`、校验清单 | 备份范围、来源和完整性记录 |

真实私钥在 `private-secrets`，没有放进客户端安装包或公开GitHub。该目录由Git忽略，桌面原文件夹已限制为当前Windows用户和SYSTEM访问。复制、移动或压缩后要自行保管副本，不要当普通源码公开分享。

这里的备份是交付当天的快照。日后新增、续期、禁用或解绑授权后，需要重新备份数据库；修改Secret后，需要更新自己的私密备份。只有源码和私钥，而没有最新数据库及原域名控制权，不能完整恢复客户授权状态。

## 2. 根据坏了什么选择操作

| 情况 | 正确做法 |
|---|---|
| Pages部署失败，项目/数据库都还在 | 重新构建部署，复用当前DB，不导入旧SQL |
| Pages项目被删除，数据库还在 | 重建Pages项目，重新绑定原DB，恢复Secret和域名 |
| 数据库也被删除或损坏 | 新建空D1，导入最新SQL，绑定新DB，再恢复Secret和服务 |
| 整个Cloudflare账号不可用 | 用新账号部署，恢复数据库、原私钥和原域名/DNS；更新wrangler中的数据库ID |

优先使用仍然正常的数据库。不要把旧备份导入现有生产DB，不要清空生产DB，也不要重新生成签名私钥替代本包的原钥。

## 3. 准备Windows构建环境

1. 从 [Node.js官网](https://nodejs.org/en/download)安装Node.js 22或24 LTS，选择Windows x64安装器。
2. 安装完关闭旧PowerShell，再打开新的PowerShell。
3. 进入本源码文件夹。在资源管理器地址栏输入 `powershell` 后回车即可在该目录打开。
4. 执行 `node --version` 和 `npm.cmd --version`，应出现版本号。
5. 双击 `一键构建授权服务.cmd`。它安装固定依赖并编译TypeScript、检查页面JS语法。成功后提示“授权服务构建完成”。
6. 构建不部署、不清空数据库、不生成客户授权码。

## 4. 登录自己的Cloudflare账号

在源码目录的PowerShell执行：

```powershell
npx.cmd wrangler login
npx.cmd wrangler whoami
```

第一条会打开浏览器，登录Cloudflare并允许Wrangler管理Pages和D1。第二条显示当前账号，确认是你要恢复到的账号。不要把Cloudflare登录令牌写进源码或发给客户。

当前原账号ID可在恢复配置中找到。换账号时，数据库ID和项目绑定也要随之更新；账号名称相同不代表数据库相同。

## 5. 项目和数据库都在：最短恢复路线

1. 登录Cloudflare控制台，进入 **Workers & Pages → cleanc-license-server**。
2. 在部署列表查看当前生产部署和失败原因。如果只是网络/API偶发错误，可重新部署。
3. 在 **Settings → Bindings** 确认D1绑定名称是 **DB**，目标是原来的 **cleanc-license**。
4. 在 **Settings → Variables and Secrets** 确认五项Secret仍在。不要修改正常的原密钥。
5. 双击 `一键部署授权服务.cmd`。它重新构建、提交生产部署，不导入数据库，也不替换Secret。
6. 部署完成后检查第10节。若Secret确实丢失，才用第8节或“一键恢复云端Secret并部署”。

## 6. Pages项目没了，原D1还在

### 方式A：通过GitHub恢复

1. Cloudflare **Workers & Pages → Create application → Pages → Connect to Git**。界面名称可能随控制台更新稍有变化。
2. 连接你自己的GitHub账号，选择 **wwz554/CleanC-License-Server**。
3. 生产分支选 **main**，项目名尽量使用 **cleanc-license-server**。
4. Framework preset选 **None**；Build command填 **npm run build**；Build output directory填 **public**；Root directory留空。
5. 保存。首次部署在未绑定DB/Secret前可能未能提供服务，继续完成下面配置后重新部署。
6. 在项目 **Settings → Bindings → Add binding → D1 database**：Variable name填 **DB**，选择现有 **cleanc-license**。
7. 完成第8节Secret和变量配置，然后在Deployments重新部署main。

### 方式B：通过本地源码直接上传

源码已包含CLI部署脚本。新项目可以先执行：

```powershell
npx.cmd wrangler pages project create cleanc-license-server --production-branch main
```

随后在控制台绑定原D1、添加第8节配置，再执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-server.ps1
```

CLI使用Pages Functions，并自动编译functions目录。不要只把public目录手动拖到控制台上传静态网页，那样不会恢复授权API。

## 7. D1也没了：先恢复授权和绑定数据

1. Cloudflare进入 **Storage & Databases → D1**，新建数据库，例如 **cleanc-license**。如果原名字已被占用，可用另一个名字。
2. 这是新的空数据库。记录数据库的 **Database ID**。
3. 打开源码中的 `wrangler.toml`，找到 `[env.production]` 下的 `[[env.production.d1_databases]]`：保持 `binding = "DB"`，把 `database_id` 改为新数据库ID，并把 `database_name` 改为新的数据库名字。不要把数据库ID填成账号ID。
4. 在源码PowerShell执行下列命令。数据库名字不同就替换 `cleanc-license`。

```powershell
npx.cmd wrangler d1 execute cleanc-license --remote --file ".\private-secrets\database-after-upgrade.sql"
```

5. 命令成功后，在D1控制台检查 `licenses`、`devices`、`system_settings` 等表已经出现。核对授权数量和绑定数量。
6. 原授权的 `activated_at`、`expires_at` 和设备公钥必须保留。不要把所有授权重新生成，不要把首次激活时间置空。
7. 绑定此新数据库到Pages的 **DB**，完成Secret配置并重新部署。

若只有升级前SQL副本也可以向新的空D1恢复。新版本启动会添加产品字段，把旧授权保留为CleanC；该旧副本不会包含备份日期后新建或修改的授权，因此优先选择最新升级后副本。

SQL导入失败时先看错误，不要反复向已有数据的库导入，不要删除原备份。D1导出/导入参考 [Cloudflare官方说明](https://developers.cloudflare.com/d1/best-practices/import-export-data/)。

## 8. 把原私钥和Secret添加回Cloudflare

### 控制台逐项添加

进入 **Workers & Pages → 项目 → Settings → Variables and Secrets**。选择生产环境 **Production**。添加以下项目时选择Secret/Encrypt：

| 名称（大小写必须一致） | 复制哪个文件的内容 |
|---|---|
| `LICENSE_SIGNING_PRIVATE_KEY` | `private-secrets/LICENSE_SIGNING_PRIVATE_KEY.pem` 的完整内容，包含BEGIN/END两行及换行 |
| `OFFLINE_RSA_PRIVATE_KEY` | `private-secrets/OFFLINE_RSA_PRIVATE_KEY.pem` 的完整内容，包含BEGIN/END两行及换行 |
| `ADMIN_PASSWORD` | `private-secrets/ADMIN_PASSWORD.txt` 的原值 |
| `SESSION_SECRET` | `private-secrets/SESSION_SECRET.txt` 的原值 |
| `TURNSTILE_SECRET` | `private-secrets/TURNSTILE_SECRET.txt` 的原值 |

用记事本打开文件，Ctrl+A、Ctrl+C，粘贴到Cloudflare的Value输入框，然后保存。不要给PEM再加引号，不要把文件路径当Value，不要只复制中间一行。两把私钥用途不同，不能互换。

普通变量（不选择Encrypt）：

| 变量 | 值 |
|---|---|
| `TURNSTILE_SITE_KEY` | 当前 `wrangler.toml` 里的原公开Site Key |
| `LEASE_HOURS` | `72` |
| `BOOTSTRAP_BASE_URL` | `https://cleanc-license-server.pages.dev`；项目改名时使用实际稳定pages.dev地址 |
| `APP_NAME` | `CleanC`（兼容原管理页，后台已区分网工拼音产品） |

当前服务不需要 `DEVICE_PROOF_SECRET`。后台登录需要Turnstile。确认Turnstile widget的Hostname Management允许新pages.dev地址及 **wwz554.ccwu.cc**。若换账号后无法复用原Turnstile widget，可以新建widget并更新Site Key与Secret；这不会改变签名密钥和客户授权，但要更新自己的备份。

### 本地批量恢复

本包有包含准确原值的 `private-secrets/cloudflare-secrets.json`。登录正确账号、建好项目和DB后，双击 **一键恢复云端Secret并部署.cmd**。

脚本先核对原P-256/RSA私钥与配套公钥，再批量上传五项Secret并重新部署。它不会向现有数据库导入SQL。项目名字不同可以执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\deploy-server.ps1 -ProjectName "你的实际项目名" -RestoreSecrets
```

Cloudflare Secret保存后无法通过管理API读取原值。以后改Secret时请同时更新自己的私密备份；本次已通过临时的加密备份流程取回原值，临时入口及对应部署已移除。官方管理方式见 [Workers/Pages Secret说明](https://developers.cloudflare.com/workers/configuration/secrets/)。

## 9. 恢复原域名

1. 在Pages项目的 **Custom domains** 中添加 **wwz554.ccwu.cc**。
2. 按Cloudflare提示，在你管理该域名的DNS系统中设置指向当前项目pages.dev的CNAME，等待域名证书显示Active。
3. 将该域名加入Turnstile允许的Hostname列表。
4. D1中 `PRIMARY_BASE_URL` 若保留为 `https://wwz554.ccwu.cc`，必须确认该地址能访问新服务。
5. 在后台“设置 → 域名与API”核对主地址。需要变更主地址时用后台检测保存，不要绕过HTTPS校验。

客户端内置原地址和稳定Pages入口。恢复旧域名/项目入口，并继续使用原签名私钥后，旧客户端才能找到并信任新服务。如果原域名和原Pages入口都失去控制，仅拿到私钥仍不能让旧客户端自动找到另一个地址，届时需要更新客户端入口。

## 10. 部署完应看到什么

这些检查不需要消耗真实授权码：

- 打开 `https://wwz554.ccwu.cc/api/v1/health`：应显示apiVersion 3、leaseVersion 4、challenge-refresh及CleanC/NetIME产品。
- 打开 `https://wwz554.ccwu.cc/bootstrap/v1/config`：应有signedPayload和signature，原公钥仍能验证。
- 打开 `https://wwz554.ccwu.cc/admin`：应出现带Turnstile的管理员登录页面。
- 登录后台“授权管理”：产品选择中有CleanC和网工拼音，旧授权、日期和设备绑定数量保持。
- 后台分别生成授权时，CleanC为CLC-前缀，网工拼音为NETIME-前缀；产品列、设备列和筛选一致。

只有在你自己准备给设备授权时才使用实际授权码。网工拼音在托盘授权页激活；授权前普通拼音可用，工程面板与卡片未启用。失效租约联网刷新后，原设备私钥与数据库公钥一致时可续租，不必重新创建授权。

客户端的 `%LocalAppData%\NetIME\Licensing` 是当前Windows用户的设备身份，服务器恢复不应删除它。若本机身份确实损坏，在服务器解绑对应旧设备后，再使用客户端“恢复授权身份”按钮；旧本机文件会备份，并要求重新激活。

## 11. 常见报错

| 报错 | 处理 |
|---|---|
| `D1_BINDING_MISSING` | D1绑定名称必须是DB，完成绑定后重新部署 |
| `SERVER_NOT_CONFIGURED` | 检查Production环境五项Secret、普通变量及部署是否已更新 |
| `SIGNING_KEY_MISSING` / 签名不匹配 | 粘贴原P-256完整PEM；核对配套公钥，不能拿RSA替代 |
| `LICENSE_PRODUCT_MISMATCH` | 产品不对应；不能用CleanC码激活网工拼音，也不能只改码前缀 |
| `LICENSE_ALREADY_BOUND` | 后台核对并解绑旧设备，再由用户激活 |
| `DEVICE_KEY_MISMATCH` | 保留本机身份文件，核对账号/系统变化，不在后台随意替换设备公钥 |
| 后台Turnstile失败 | 核对Site Key/Secret及Hostname，换账号可能需新建widget |
| API偶发500或传输EOF | 查看Cloudflare部署状态和错误日志后重试，保留数据库与原钥 |
| Pages静态页有了但API404 | 确认functions目录参与CLI/Git构建，不能只上传静态public |

## 12. 建立日常备份习惯

完成授权新增、续期、解绑或禁用后，双击 **一键备份授权数据库.cmd**。它在private-secrets保存带时间的新SQL并显示SHA256。D1导出可能短暂占用数据库，请选择授权请求较少时操作。

另外保留本完整源码、两把原私钥、最新Secret原值、域名/DNS管理权、Cloudflare/GitHub账户恢复方式和最新SQL的安全副本。源码本身可放GitHub，private-secrets不能推送。不要为了恢复服务重新生成原客户授权码或签名密钥。
