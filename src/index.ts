export interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  SESSION_SECRET: string;
  TURNSTILE_SECRET: string;
  LICENSE_SIGNING_PRIVATE_KEY: string;
  APP_NAME?: string;
  TURNSTILE_SITE_KEY?: string;
  LEASE_HOURS?: string;
}

type Json = Record<string, unknown>;
const API_VERSION = 1;
const enc = new TextEncoder();
const dec = new TextDecoder();

const json = (data: unknown, status = 200, extra: HeadersInit = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", ...extra },
});
const html = (body: string, status = 200) => new Response(body, {
  status,
  headers: { "content-type": "text/html; charset=utf-8", ...securityHeaders() },
});
const now = () => new Date().toISOString();
const uid = () => crypto.randomUUID();
const b64url = (bytes: ArrayBuffer | Uint8Array) => {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = ""; for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
const fromB64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const safeEq = (a: string, b: string) => {
  const x = enc.encode(a), y = enc.encode(b); if (x.length !== y.length) return false;
  let d = 0; for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i]; return d === 0;
};

function securityHeaders(): Record<string, string> {
  return {
    "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
  };
}

async function hmac(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}

async function makeSession(env: Env): Promise<string> {
  const payload = b64url(enc.encode(JSON.stringify({ exp: Date.now() + 8 * 3600_000, nonce: uid() })));
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}

async function validSession(req: Request, env: Env): Promise<boolean> {
  const raw = (req.headers.get("cookie") || "").split(/;\s*/).find(v => v.startsWith("cleanc_session="))?.split("=")[1];
  if (!raw) return false;
  const [p, sig] = raw.split("."); if (!p || !sig || !safeEq(sig, await hmac(env.SESSION_SECRET, p))) return false;
  try { return JSON.parse(dec.decode(fromB64(p))).exp > Date.now(); } catch { return false; }
}

async function csrfFor(req: Request, env: Env): Promise<string> {
  const cookie = req.headers.get("cookie") || "";
  const session = cookie.split(/;\s*/).find(v => v.startsWith("cleanc_session="))?.split("=")[1] || "";
  return hmac(env.SESSION_SECRET, `csrf:${session}`);
}

async function requireCsrf(req: Request, env: Env): Promise<boolean> {
  const got = req.headers.get("x-csrf-token") || "";
  return safeEq(got, await csrfFor(req, env));
}

async function audit(env: Env, req: Request, eventType: string, detail: unknown = null, licenseId: string | null = null, deviceId: string | null = null) {
  const ip = req.headers.get("cf-connecting-ip") || null;
  await env.DB.prepare("INSERT INTO audit_logs (id,event_type,ip,license_id,device_id,detail,created_at) VALUES (?,?,?,?,?,?,?)")
    .bind(uid(), eventType, ip, licenseId, deviceId, detail == null ? null : JSON.stringify(detail), now()).run();
}

async function verifyTurnstile(req: Request, env: Env, token: string): Promise<boolean> {
  if (!env.TURNSTILE_SECRET || env.TURNSTILE_SECRET === "DISABLED") return true;
  const form = new FormData(); form.set("secret", env.TURNSTILE_SECRET); form.set("response", token || "");
  const ip = req.headers.get("cf-connecting-ip"); if (ip) form.set("remoteip", ip);
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    const j = await r.json() as { success?: boolean }; return !!j.success;
  } catch { return false; }
}

async function setting(env: Env, key: string): Promise<string | null> {
  const r = await env.DB.prepare("SELECT setting_value FROM system_settings WHERE setting_key=?").bind(key).first<{setting_value:string}>();
  return r?.setting_value ?? null;
}
async function canonical(req: Request, env: Env): Promise<string> {
  return (await setting(env, "PRIMARY_BASE_URL")) || new URL(req.url).origin;
}

function normalizeDomain(input: string): string | null {
  try {
    const raw = /^https?:\/\//i.test(input) ? input : `https://${input}`;
    const u = new URL(raw); if (u.protocol !== "https:" || u.username || u.password || u.pathname !== "/" || u.search || u.hash) return null;
    const h = u.hostname.toLowerCase(); if (h === "localhost" || /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h)) return null;
    return `https://${h}${u.port ? `:${u.port}` : ""}`;
  } catch { return null; }
}

async function importSigningKey(pem: string): Promise<CryptoKey> {
  const body = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+/g, "");
  return crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(body), c => c.charCodeAt(0)), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}
async function signObject(env: Env, obj: Json): Promise<string> {
  const key = await importSigningKey(env.LICENSE_SIGNING_PRIVATE_KEY);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(JSON.stringify(obj)));
  return b64url(sig);
}

function randomKey(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(16); crypto.getRandomValues(bytes);
  const part = (offset: number) => Array.from(bytes.slice(offset, offset + 4), b => chars[b % chars.length]).join("");
  return `CLC-${part(0)}-${part(4)}-${part(8)}-${part(12)}`;
}

async function apiError(code: string, message: string, status = 400) { return json({ success: false, code, message }, status); }

async function activate(req: Request, env: Env) {
  const body = await req.json() as any;
  const key = String(body.licenseKey || "").trim(); const deviceId = String(body.deviceId || "").trim();
  if (!key || !deviceId) return apiError("INVALID_REQUEST", "缺少授权码或设备标识");
  const lic = await env.DB.prepare("SELECT * FROM licenses WHERE license_key=? AND deleted_at IS NULL").bind(key).first<any>();
  if (!lic) { await audit(env, req, "LICENSE_REJECTED", { code: "LICENSE_NOT_FOUND" }); return apiError("LICENSE_NOT_FOUND", "授权码不存在", 404); }
  if (String(lic.status).toLowerCase() !== "active") return apiError("LICENSE_DISABLED", "授权不可用", 403);
  const current = new Date();
  if (lic.expires_at && new Date(lic.expires_at) <= current) return apiError("LICENSE_EXPIRED", "授权已过期", 403);
  let dev = await env.DB.prepare("SELECT * FROM devices WHERE license_id=? AND device_id=?").bind(lic.id, deviceId).first<any>();
  if (dev?.revoked_at) return apiError("DEVICE_REVOKED", "设备已解绑", 403);
  if (!dev) {
    const count = await env.DB.prepare("SELECT COUNT(*) c FROM devices WHERE license_id=? AND revoked_at IS NULL").bind(lic.id).first<{c:number}>();
    if ((count?.c || 0) >= lic.max_devices) return apiError("DEVICE_LIMIT_REACHED", "已达到设备数量限制", 409);
    const activatedAt = lic.activated_at || now();
    let expiresAt = lic.expires_at;
    if (!lic.activated_at && lic.license_type === "duration" && lic.duration_days) expiresAt = new Date(Date.now() + Number(lic.duration_days) * 86400000).toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO devices (id,license_id,device_id,public_key,device_name,windows_version,app_version,first_seen_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?,?)")
        .bind(uid(), lic.id, deviceId, body.devicePublicKey || null, body.deviceName || null, body.windowsVersion || null, body.appVersion || null, now(), now()),
      env.DB.prepare("UPDATE licenses SET activated_at=COALESCE(activated_at,?), expires_at=COALESCE(?,expires_at), updated_at=? WHERE id=?").bind(activatedAt, expiresAt, now(), lic.id),
    ]);
    await audit(env, req, "DEVICE_BOUND", { deviceName: body.deviceName || null }, lic.id, deviceId);
  } else {
    await env.DB.prepare("UPDATE devices SET last_seen_at=?, app_version=?, windows_version=? WHERE id=?").bind(now(), body.appVersion || dev.app_version, body.windowsVersion || dev.windows_version, dev.id).run();
  }
  const leaseHours = Math.max(1, Number(env.LEASE_HOURS || 72));
  const lease: Json = { version: 1, licenseId: lic.id, deviceId, edition: lic.edition, features: ["clean","scan","optimize"], issuedAt: now(), expiresAt: new Date(Date.now() + leaseHours * 3600000).toISOString(), nonce: uid() };
  const signature = await signObject(env, lease);
  await audit(env, req, "LICENSE_VALIDATED", null, lic.id, deviceId);
  return json({ success: true, lease, signature, canonicalBaseUrl: await canonical(req, env) });
}

async function validate(req: Request, env: Env) { return activate(req, env); }

async function challenge(req: Request, env: Env) {
  const body = await req.json() as any; if (!body.deviceId) return apiError("INVALID_REQUEST", "缺少设备标识");
  const nonceBytes = new Uint8Array(32); crypto.getRandomValues(nonceBytes); const nonce = b64url(nonceBytes); const expiresAt = new Date(Date.now() + 5 * 60000).toISOString();
  await env.DB.prepare("INSERT INTO device_challenges (id,device_id,nonce,expires_at,created_at) VALUES (?,?,?,?,?)").bind(uid(), body.deviceId, nonce, expiresAt, now()).run();
  return json({ success: true, nonce, expiresAt });
}

async function deviceVerify(req: Request, env: Env) {
  const b = await req.json() as any; const d = await env.DB.prepare("SELECT * FROM devices WHERE device_id=? AND revoked_at IS NULL ORDER BY last_seen_at DESC LIMIT 1").bind(b.deviceId || "").first<any>();
  if (!d?.public_key) return apiError("INVALID_DEVICE_SIGNATURE", "设备公钥不存在", 403);
  const c = await env.DB.prepare("SELECT * FROM device_challenges WHERE device_id=? AND nonce=? ORDER BY created_at DESC LIMIT 1").bind(b.deviceId || "", b.nonce || "").first<any>();
  if (!c || new Date(c.expires_at) <= new Date()) return apiError("INVALID_DEVICE_SIGNATURE", "Challenge无效或已过期", 403);
  try {
    const pubBody = String(d.public_key).replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, "");
    const pub = await crypto.subtle.importKey("spki", Uint8Array.from(atob(pubBody), x => x.charCodeAt(0)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, fromB64(String(b.signature || "")), enc.encode(String(b.nonce || "")));
    if (!ok) return apiError("INVALID_DEVICE_SIGNATURE", "设备签名验证失败", 403);
    await env.DB.prepare("DELETE FROM device_challenges WHERE id=?").bind(c.id).run();
    return json({ success: true, verified: true });
  } catch { return apiError("INVALID_DEVICE_SIGNATURE", "设备签名格式错误", 403); }
}

async function adminApi(req: Request, env: Env, path: string): Promise<Response> {
  if (!await validSession(req, env)) return json({ success: false, code: "UNAUTHORIZED" }, 401);
  if (["POST","PUT","PATCH","DELETE"].includes(req.method) && !await requireCsrf(req, env)) return json({ success: false, code: "CSRF_FAILED" }, 403);
  if (path === "/admin/api/session" && req.method === "GET") return json({ success: true, csrfToken: await csrfFor(req, env) });
  if (path === "/admin/api/dashboard" && req.method === "GET") {
    const rows = await env.DB.prepare("SELECT COUNT(*) total, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) active, SUM(CASE WHEN status='disabled' THEN 1 ELSE 0 END) disabled FROM licenses WHERE deleted_at IS NULL").first<any>();
    const devs = await env.DB.prepare("SELECT COUNT(*) c FROM devices WHERE revoked_at IS NULL").first<any>();
    return json({ success: true, stats: { total: rows?.total || 0, active: rows?.active || 0, disabled: rows?.disabled || 0, devices: devs?.c || 0 } });
  }
  if (path === "/admin/api/licenses" && req.method === "GET") {
    const { results } = await env.DB.prepare("SELECT l.*, (SELECT COUNT(*) FROM devices d WHERE d.license_id=l.id AND d.revoked_at IS NULL) device_count FROM licenses l WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 500").all();
    return json({ success: true, licenses: results });
  }
  if (path === "/admin/api/licenses" && req.method === "POST") {
    const b = await req.json() as any; const count = Math.min(1000, Math.max(1, Number(b.count || 1))); const out: string[] = [];
    for (let i = 0; i < count; i++) {
      const key = count === 1 && b.licenseKey ? String(b.licenseKey).trim() : randomKey(); if (!key) continue;
      const id = uid(); const type = ["permanent","duration","fixed"].includes(b.licenseType) ? b.licenseType : "permanent";
      const expires = type === "fixed" && b.expiresAt ? new Date(b.expiresAt).toISOString() : null;
      await env.DB.prepare("INSERT INTO licenses (id,license_key,edition,status,license_type,duration_days,expires_at,max_devices,note,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
        .bind(id, key, b.edition || "pro", "active", type, type === "duration" ? Number(b.durationDays || 365) : null, expires, Math.max(1, Number(b.maxDevices || 1)), b.note || null, now(), now()).run();
      out.push(key); await audit(env, req, count > 1 ? "LICENSE_BATCH_CREATED" : "LICENSE_CREATED", { licenseKey: key }, id);
    }
    return json({ success: true, licenseKeys: out });
  }
  const m = path.match(/^\/admin\/api\/licenses\/([^/]+)\/(disable|enable)$/);
  if (m && req.method === "POST") {
    const status = m[2] === "disable" ? "disabled" : "active"; await env.DB.prepare("UPDATE licenses SET status=?,updated_at=? WHERE id=?").bind(status, now(), m[1]).run();
    await audit(env, req, status === "disabled" ? "LICENSE_DISABLED" : "LICENSE_ENABLED", null, m[1]); return json({ success: true });
  }
  const unbind = path.match(/^\/admin\/api\/devices\/([^/]+)\/revoke$/);
  if (unbind && req.method === "POST") { await env.DB.prepare("UPDATE devices SET revoked_at=? WHERE id=?").bind(now(), unbind[1]).run(); await audit(env, req, "DEVICE_REVOKED", { id: unbind[1] }); return json({ success: true }); }
  if (path === "/admin/api/devices" && req.method === "GET") { const { results } = await env.DB.prepare("SELECT d.*,l.license_key FROM devices d JOIN licenses l ON l.id=d.license_id ORDER BY d.last_seen_at DESC LIMIT 500").all(); return json({ success: true, devices: results }); }
  if (path === "/admin/api/logs" && req.method === "GET") { const { results } = await env.DB.prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500").all(); return json({ success: true, logs: results }); }
  if (path === "/admin/api/settings" && req.method === "GET") return json({ success: true, canonicalBaseUrl: await canonical(req, env), currentOrigin: new URL(req.url).origin, turnstileSiteKey: env.TURNSTILE_SITE_KEY || "" });
  if (path === "/admin/api/settings/domain" && req.method === "POST") {
    const b = await req.json() as any; if (!safeEq(String(b.password || ""), env.ADMIN_PASSWORD)) return json({ success: false, code: "BAD_PASSWORD" }, 403);
    if (!await verifyTurnstile(req, env, String(b.turnstileToken || ""))) return json({ success: false, code: "TURNSTILE_FAILED" }, 403);
    const next = normalizeDomain(String(b.baseUrl || "")); if (!next) return json({ success: false, code: "INVALID_DOMAIN" }, 400);
    const old = await setting(env, "PRIMARY_BASE_URL");
    await env.DB.batch([
      env.DB.prepare("INSERT INTO system_settings(setting_key,setting_value,updated_at) VALUES('PRIMARY_BASE_URL',?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at").bind(next, now()),
      env.DB.prepare("INSERT INTO domain_history(id,old_url,new_url,ip,created_at) VALUES(?,?,?,?,?)").bind(uid(), old, next, req.headers.get("cf-connecting-ip"), now()),
    ]); await audit(env, req, "DOMAIN_CHANGED", { old, next }); return json({ success: true, canonicalBaseUrl: next });
  }
  if (path === "/admin/api/settings/domain/rollback" && req.method === "POST") {
    const b = await req.json() as any; if (!safeEq(String(b.password || ""), env.ADMIN_PASSWORD) || !await verifyTurnstile(req, env, String(b.turnstileToken || ""))) return json({ success:false },403);
    const old = await setting(env,"PRIMARY_BASE_URL"); await env.DB.prepare("DELETE FROM system_settings WHERE setting_key='PRIMARY_BASE_URL'").run(); await audit(env, req,"DOMAIN_ROLLBACK",{old,next:new URL(req.url).origin}); return json({success:true,canonicalBaseUrl:new URL(req.url).origin});
  }
  return json({ success: false, code: "NOT_FOUND" }, 404);
}

async function login(req: Request, env: Env): Promise<Response> {
  const b = await req.json() as any; const okPass = safeEq(String(b.password || ""), env.ADMIN_PASSWORD); const okTs = await verifyTurnstile(req, env, String(b.turnstileToken || ""));
  if (!okPass || !okTs) { await audit(env, req, "ADMIN_LOGIN_FAILED", { passwordOk: okPass, turnstileOk: okTs }); return json({ success: false, message: "密码或验证码错误" }, 403); }
  const session = await makeSession(env); await audit(env, req, "ADMIN_LOGIN_SUCCESS");
  return json({ success: true }, 200, { "set-cookie": `cleanc_session=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800` });
}

function adminPage(env: Env): string {
  const siteKey = (env.TURNSTILE_SITE_KEY || "").replace(/"/g, "&quot;");
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CleanC License</title><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script><style>
*{box-sizing:border-box}body{margin:0;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#10203b;background:radial-gradient(circle at 10% 15%,#cbe7ff 0,transparent 35%),radial-gradient(circle at 90% 5%,#eadcff 0,transparent 35%),linear-gradient(135deg,#f7fbff,#eef4ff);min-height:100vh}.glass{background:rgba(255,255,255,.58);backdrop-filter:blur(28px) saturate(150%);-webkit-backdrop-filter:blur(28px) saturate(150%);border:1px solid rgba(255,255,255,.75);box-shadow:0 24px 80px rgba(34,70,140,.14),inset 0 1px 0 #fff;border-radius:28px}.login{width:min(420px,calc(100% - 32px));padding:34px;position:absolute;left:50%;top:50%;transform:translate(-50%,-50%)}.logo{width:58px;height:58px;border-radius:18px;display:grid;place-items:center;font-size:28px;font-weight:800;color:white;background:linear-gradient(145deg,#4b8cff,#7d5cff);box-shadow:0 12px 30px #6d7cff55}.muted{color:#6f7d96}input,select,button,textarea{font:inherit}input,select,textarea{width:100%;padding:12px 14px;border-radius:14px;border:1px solid #dbe4f4;background:#ffffffb8;outline:none}.btn{border:0;border-radius:14px;padding:11px 16px;cursor:pointer;font-weight:650}.primary{background:linear-gradient(135deg,#4d88ff,#735cff);color:#fff}.danger{background:#fff0f2;color:#c73555}.app{display:none;min-height:100vh;padding:20px}.sidebar{width:230px;padding:22px;position:fixed;top:20px;bottom:20px}.nav button{display:block;width:100%;text-align:left;margin:6px 0;background:transparent;color:#536078}.nav button.active{background:#ffffffc9;color:#315fc5}.main{margin-left:250px;padding:4px 0 40px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{padding:20px}.stat b{font-size:30px}.panel{margin-top:16px;padding:20px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row>*{flex:1}.row .btn{flex:0 0 auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid #e5ebf5}code{font-family:ui-monospace,Consolas,monospace;background:#eef3ff;padding:3px 6px;border-radius:7px}.pill{padding:4px 9px;border-radius:999px;background:#eaf2ff}.section{display:none}.section.active{display:block}@media(max-width:850px){.sidebar{position:static;width:auto;margin-bottom:14px}.main{margin-left:0}.grid{grid-template-columns:repeat(2,1fr)}.app{padding:12px}}@media(max-width:520px){.grid{grid-template-columns:1fr}}
</style></head><body><div id="login" class="login glass"><div class="logo">C</div><h1>CleanC License</h1><p class="muted">管理员控制台</p><input id="password" type="password" placeholder="管理员密码"><div style="height:14px"></div><div class="cf-turnstile" data-sitekey="${siteKey}"></div><div style="height:14px"></div><button class="btn primary" style="width:100%" onclick="doLogin()">登录</button><p id="loginMsg" class="muted"></p></div>
<div id="app" class="app"><aside class="sidebar glass"><div class="row" style="justify-content:flex-start"><div class="logo" style="width:42px;height:42px;border-radius:14px;font-size:20px">C</div><div><b>CleanC</b><div class="muted" style="font-size:12px">License Server</div></div></div><div class="nav" style="margin-top:22px"><button class="btn active" data-tab="dashboard">仪表盘</button><button class="btn" data-tab="licenses">授权管理</button><button class="btn" data-tab="devices">设备管理</button><button class="btn" data-tab="logs">操作日志</button><button class="btn" data-tab="settings">设置</button></div></aside><main class="main"><div class="top"><div><h2 id="title">仪表盘</h2><div class="muted">CleanC 授权服务管理中心</div></div></div>
<section id="dashboard" class="section active"><div class="grid"><div class="card glass stat"><span class="muted">总授权</span><br><b id="sTotal">-</b></div><div class="card glass stat"><span class="muted">有效授权</span><br><b id="sActive">-</b></div><div class="card glass stat"><span class="muted">已禁用</span><br><b id="sDisabled">-</b></div><div class="card glass stat"><span class="muted">绑定设备</span><br><b id="sDevices">-</b></div></div></section>
<section id="licenses" class="section"><div class="panel glass"><div class="row"><input id="customKey" placeholder="自定义授权码（留空则随机）"><select id="licenseType"><option value="permanent">永久</option><option value="duration">激活后 N 天</option><option value="fixed">固定到期</option></select><input id="durationDays" type="number" value="365" placeholder="天数"><input id="maxDevices" type="number" value="1" min="1" placeholder="设备数"><input id="batchCount" type="number" value="1" min="1" max="1000" placeholder="数量"><button class="btn primary" onclick="createLicense()">生成授权</button></div></div><div class="panel glass" style="overflow:auto"><table><thead><tr><th>授权码</th><th>状态</th><th>类型</th><th>设备</th><th>创建</th><th>操作</th></tr></thead><tbody id="licenseRows"></tbody></table></div></section>
<section id="devices" class="section"><div class="panel glass" style="overflow:auto"><table><thead><tr><th>设备</th><th>授权码</th><th>Windows</th><th>App</th><th>最近在线</th><th>操作</th></tr></thead><tbody id="deviceRows"></tbody></table></div></section>
<section id="logs" class="section"><div class="panel glass" style="overflow:auto"><table><thead><tr><th>时间</th><th>事件</th><th>IP</th><th>详情</th></tr></thead><tbody id="logRows"></tbody></table></div></section>
<section id="settings" class="section"><div class="panel glass"><h3>域名与 API</h3><p>当前访问地址：<code id="currentOrigin">-</code></p><p>正式授权地址：<code id="canonicalUrl">-</code></p><p>Bootstrap：<code id="bootstrapUrl">-</code></p><div class="row"><input id="newDomain" placeholder="license.example.com"><input id="confirmPassword" type="password" placeholder="管理员密码"><button class="btn primary" onclick="saveDomain()">检测并保存</button><button class="btn danger" onclick="rollbackDomain()">恢复 workers.dev</button></div><p class="muted">域名变更会要求管理员密码和 Turnstile；请先在 Cloudflare Worker Custom Domain 与 Turnstile Hostname Management 中配置新域名。</p></div><div class="panel glass"><h3>API 信息</h3><div id="apiList"></div></div></section></main></div>
<script>let csrf='';const $=id=>document.getElementById(id);async function req(path,opt={}){opt.headers={...(opt.headers||{}),'content-type':'application/json','x-csrf-token':csrf};const r=await fetch(path,opt);return r.json()}async function boot(){const s=await fetch('/admin/api/session');if(!s.ok)return;csrf=(await s.json()).csrfToken;$('login').style.display='none';$('app').style.display='block';await loadDashboard()}async function doLogin(){const token=document.querySelector('[name="cf-turnstile-response"]')?.value||'';const r=await req('/admin/api/login',{method:'POST',body:JSON.stringify({password:$('password').value,turnstileToken:token})});if(r.success){location.reload()}else $('loginMsg').textContent=r.message||'登录失败'}async function loadDashboard(){const r=await req('/admin/api/dashboard');if(r.success){$('sTotal').textContent=r.stats.total;$('sActive').textContent=r.stats.active;$('sDisabled').textContent=r.stats.disabled;$('sDevices').textContent=r.stats.devices}}async function loadLicenses(){const r=await req('/admin/api/licenses');$('licenseRows').innerHTML=(r.licenses||[]).map(x=>`<tr><td><code>${x.license_key}</code></td><td><span class="pill">${x.status}</span></td><td>${x.license_type}</td><td>${x.device_count}/${x.max_devices}</td><td>${x.created_at?.slice(0,10)||''}</td><td><button class="btn" onclick="toggleLic('${x.id}','${x.status==='active'?'disable':'enable'}')">${x.status==='active'?'禁用':'恢复'}</button></td></tr>`).join('')}async function createLicense(){const r=await req('/admin/api/licenses',{method:'POST',body:JSON.stringify({licenseKey:$('customKey').value,licenseType:$('licenseType').value,durationDays:+$('durationDays').value,maxDevices:+$('maxDevices').value,count:+$('batchCount').value})});if(r.success){alert('已生成 '+r.licenseKeys.length+' 个授权码\n'+r.licenseKeys.slice(0,20).join('\n'));loadLicenses();loadDashboard()}else alert(r.code||'失败')}async function toggleLic(id,op){await req('/admin/api/licenses/'+id+'/'+op,{method:'POST',body:'{}'});loadLicenses();loadDashboard()}async function loadDevices(){const r=await req('/admin/api/devices');$('deviceRows').innerHTML=(r.devices||[]).map(x=>`<tr><td>${x.device_name||x.device_id}</td><td><code>${x.license_key}</code></td><td>${x.windows_version||''}</td><td>${x.app_version||''}</td><td>${x.last_seen_at||''}</td><td>${x.revoked_at?'已解绑':`<button class="btn danger" onclick="revokeDevice('${x.id}')">解绑</button>`}</td></tr>`).join('')}async function revokeDevice(id){if(confirm('确认解绑此设备？')){await req('/admin/api/devices/'+id+'/revoke',{method:'POST',body:'{}'});loadDevices();loadDashboard()}}async function loadLogs(){const r=await req('/admin/api/logs');$('logRows').innerHTML=(r.logs||[]).map(x=>`<tr><td>${x.created_at}</td><td>${x.event_type}</td><td>${x.ip||''}</td><td><code>${(x.detail||'').replaceAll('<','&lt;')}</code></td></tr>`).join('')}async function loadSettings(){const r=await req('/admin/api/settings');$('currentOrigin').textContent=r.currentOrigin;$('canonicalUrl').textContent=r.canonicalBaseUrl;$('bootstrapUrl').textContent=r.currentOrigin+'/bootstrap/v1/config';const eps=['/api/v1/license/activate','/api/v1/license/validate','/api/v1/license/refresh','/api/v1/device/challenge','/api/v1/device/verify','/api/v1/health','/api/v1/meta'];$('apiList').innerHTML=eps.map(x=>`<p><code>${r.canonicalBaseUrl+x}</code></p>`).join('')}async function saveDomain(){const token=document.querySelector('[name="cf-turnstile-response"]')?.value||'';const r=await req('/admin/api/settings/domain',{method:'POST',body:JSON.stringify({baseUrl:$('newDomain').value,password:$('confirmPassword').value,turnstileToken:token})});if(r.success){alert('主授权域名已更新');loadSettings()}else alert(r.code||'保存失败')}async function rollbackDomain(){const token=document.querySelector('[name="cf-turnstile-response"]')?.value||'';const r=await req('/admin/api/settings/domain/rollback',{method:'POST',body:JSON.stringify({password:$('confirmPassword').value,turnstileToken:token})});if(r.success){alert('已恢复当前 workers.dev / 当前 Origin');loadSettings()}else alert('验证失败')}
document.querySelectorAll('.nav button').forEach(b=>b.onclick=async()=>{document.querySelectorAll('.nav button').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.section').forEach(x=>x.classList.remove('active'));b.classList.add('active');$(b.dataset.tab).classList.add('active');$('title').textContent=b.textContent;if(b.dataset.tab==='dashboard')loadDashboard();if(b.dataset.tab==='licenses')loadLicenses();if(b.dataset.tab==='devices')loadDevices();if(b.dataset.tab==='logs')loadLogs();if(b.dataset.tab==='settings')loadSettings()});boot();</script></body></html>`;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url), path = url.pathname;
    try {
      if (path === "/api/v1/health" && req.method === "GET") return json({ status: "ok", apiVersion: API_VERSION });
      if (path === "/api/v1/meta" && req.method === "GET") return json({ appName: env.APP_NAME || "CleanC", apiVersion: API_VERSION, canonicalBaseUrl: await canonical(req, env) });
      if (path === "/bootstrap/v1/config" && req.method === "GET") { const payload: Json = { apiVersion: API_VERSION, canonicalBaseUrl: await canonical(req, env), issuedAt: now() }; return json({ ...payload, signature: await signObject(env, payload) }); }
      if (path === "/api/v1/license/activate" && req.method === "POST") return activate(req, env);
      if (["/api/v1/license/validate","/api/v1/license/refresh"].includes(path) && req.method === "POST") return validate(req, env);
      if (path === "/api/v1/device/challenge" && req.method === "POST") return challenge(req, env);
      if (path === "/api/v1/device/verify" && req.method === "POST") return deviceVerify(req, env);
      if (path === "/admin/api/login" && req.method === "POST") return login(req, env);
      if (path.startsWith("/admin/api/")) return adminApi(req, env, path);
      if (path === "/admin" || path === "/admin/" || path === "/admin/login") return html(adminPage(env));
      if (path === "/") return Response.redirect(new URL("/admin", req.url).toString(), 302);
      return json({ success: false, code: "NOT_FOUND" }, 404);
    } catch (e) {
      console.error(e); return json({ success: false, code: "SERVER_ERROR", message: "服务器内部错误" }, 500);
    }
  }
};
