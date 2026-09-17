export interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  SESSION_SECRET: string;
  TURNSTILE_SECRET: string;
  LICENSE_SIGNING_PRIVATE_KEY: string;
  APP_NAME?: string;
  TURNSTILE_SITE_KEY?: string;
  LEASE_HOURS?: string;
  BOOTSTRAP_BASE_URL?: string;
}

type JsonObject = Record<string, unknown>;
type LicenseRow = {
  id: string;
  license_key: string;
  edition: string;
  status: string;
  license_type: string;
  duration_days: number | null;
  expires_at: string | null;
  activated_at: string | null;
  max_devices: number;
};
type DeviceRow = {
  id: string;
  license_id: string;
  device_id: string;
  public_key: string | null;
  device_name: string | null;
  windows_version: string | null;
  app_version: string | null;
  revoked_at: string | null;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const nowIso = () => new Date().toISOString();
const uuid = () => crypto.randomUUID();

function b64url(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function unb64url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

function safeEqual(a: string, b: string): boolean {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

function responseHeaders(): HeadersInit {
  return {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  };
}

function json(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...responseHeaders(), ...headers },
  });
}

function fail(code: string, message: string, status = 400): Response {
  return json({ success: false, code, message }, status);
}

function securityHeaders(): HeadersInit {
  return {
    "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cache-control": "no-store",
  };
}

function html(body: string, status = 200): Response {
  return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", ...securityHeaders() } });
}

async function readJson(req: Request): Promise<Record<string, any>> {
  const type = req.headers.get("content-type") || "";
  if (!type.toLowerCase().includes("application/json")) throw new Error("INVALID_CONTENT_TYPE");
  return await req.json() as Record<string, any>;
}

async function hmac(secret: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, encoder.encode(text)));
}

async function createSession(env: Env): Promise<string> {
  const payload = b64url(encoder.encode(JSON.stringify({ exp: Date.now() + 8 * 3600_000, nonce: uuid() })));
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}

function getCookie(req: Request, name: string): string {
  return (req.headers.get("cookie") || "")
    .split(/;\s*/)
    .find(v => v.startsWith(name + "="))
    ?.slice(name.length + 1) || "";
}

async function validSession(req: Request, env: Env): Promise<boolean> {
  const raw = getCookie(req, "cleanc_session");
  const [payload, signature] = raw.split(".");
  if (!payload || !signature || !safeEqual(signature, await hmac(env.SESSION_SECRET, payload))) return false;
  try {
    const parsed = JSON.parse(decoder.decode(unb64url(payload))) as { exp?: number };
    return typeof parsed.exp === "number" && parsed.exp > Date.now();
  } catch {
    return false;
  }
}

async function csrfToken(req: Request, env: Env): Promise<string> {
  return hmac(env.SESSION_SECRET, `csrf:${getCookie(req, "cleanc_session")}`);
}

async function requireAdmin(req: Request, env: Env, write = false): Promise<boolean> {
  if (!await validSession(req, env)) return false;
  if (!write) return true;
  return safeEqual(req.headers.get("x-csrf-token") || "", await csrfToken(req, env));
}

async function audit(env: Env, req: Request, eventType: string, detail: unknown = null, licenseId: string | null = null, deviceId: string | null = null): Promise<void> {
  await env.DB.prepare("INSERT INTO audit_logs(id,event_type,ip,license_id,device_id,detail,created_at) VALUES(?,?,?,?,?,?,?)")
    .bind(uuid(), eventType, req.headers.get("cf-connecting-ip"), licenseId, deviceId, detail == null ? null : JSON.stringify(detail), nowIso())
    .run();
}

async function rateLimit(env: Env, key: string, max: number, seconds: number): Promise<boolean> {
  const current = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare("SELECT count,window_start FROM rate_limits WHERE bucket_key=?")
    .bind(key).first<{ count: number; window_start: number }>();
  if (!row || current - row.window_start >= seconds) {
    await env.DB.prepare("INSERT INTO rate_limits(bucket_key,count,window_start) VALUES(?,1,?) ON CONFLICT(bucket_key) DO UPDATE SET count=1,window_start=excluded.window_start")
      .bind(key, current).run();
    return true;
  }
  if (row.count >= max) return false;
  await env.DB.prepare("UPDATE rate_limits SET count=count+1 WHERE bucket_key=?").bind(key).run();
  return true;
}

async function verifyTurnstile(req: Request, env: Env, token: string): Promise<boolean> {
  if (env.TURNSTILE_SECRET === "DISABLED") return true;
  if (!env.TURNSTILE_SECRET || !token) return false;
  const form = new FormData();
  form.set("secret", env.TURNSTILE_SECRET);
  form.set("response", token);
  const ip = req.headers.get("cf-connecting-ip");
  if (ip) form.set("remoteip", ip);
  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    const result = await response.json() as { success?: boolean; hostname?: string };
    return result.success === true && result.hostname === new URL(req.url).hostname;
  } catch {
    return false;
  }
}

async function getSetting(env: Env, key: string): Promise<string | null> {
  return (await env.DB.prepare("SELECT setting_value FROM system_settings WHERE setting_key=?")
    .bind(key).first<{ setting_value: string }>())?.setting_value || null;
}

function configuredBootstrapUrl(req: Request, env: Env): string {
  const configured = String(env.BOOTSTRAP_BASE_URL || "").trim().replace(/\/$/, "");
  return configured || new URL(req.url).origin;
}

async function canonicalBaseUrl(req: Request, env: Env): Promise<string> {
  return (await getSetting(env, "PRIMARY_BASE_URL")) || configuredBootstrapUrl(req, env);
}

function normalizeHttpsOrigin(input: string): string | null {
  try {
    const url = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
    const host = url.hostname.toLowerCase();
    const privateHost = host === "localhost" || host === "::1" || /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host);
    if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || privateHost) return null;
    return `https://${host}${url.port ? `:${url.port}` : ""}`;
  } catch {
    return null;
  }
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const raw = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+/g, "");
  if (!raw) throw new Error("SIGNING_KEY_MISSING");
  return crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(raw), c => c.charCodeAt(0)), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

async function sign(env: Env, object: JsonObject): Promise<string> {
  const key = await importPrivateKey(env.LICENSE_SIGNING_PRIVATE_KEY);
  return b64url(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, encoder.encode(JSON.stringify(object))));
}

function randomLicenseKey(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const part = (start: number) => Array.from(bytes.slice(start, start + 4), b => chars[b % chars.length]).join("");
  return `CLC-${part(0)}-${part(4)}-${part(8)}-${part(12)}`;
}

function validCustomLicenseKey(value: string): boolean {
  return /^[A-Za-z0-9_-]{6,80}$/.test(value);
}

function positiveInt(value: unknown, fallback: number, max: number): number | null {
  const number = Number(value ?? fallback);
  if (!Number.isInteger(number) || number < 1 || number > max) return null;
  return number;
}

function validDate(value: unknown): string | null {
  if (!value) return null;
  const date = new Date(String(value));
  if (!Number.isFinite(date.getTime())) return null;
  return date.toISOString();
}

async function loadLicense(env: Env, key: string): Promise<LicenseRow | null> {
  return await env.DB.prepare("SELECT id,license_key,edition,status,license_type,duration_days,expires_at,activated_at,max_devices FROM licenses WHERE license_key=? AND deleted_at IS NULL")
    .bind(key).first<LicenseRow>();
}

function checkLicenseUsable(license: LicenseRow): Response | null {
  if (license.status.toLowerCase() !== "active") return fail("LICENSE_DISABLED", "授权不可用", 403);
  if (license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) return fail("LICENSE_EXPIRED", "授权已过期", 403);
  return null;
}

async function issueLease(req: Request, env: Env, license: LicenseRow, deviceId: string): Promise<Response> {
  const hoursRaw = Number(env.LEASE_HOURS || 72);
  const hours = Number.isFinite(hoursRaw) ? Math.max(1, Math.min(hoursRaw, 720)) : 72;
  const leaseLimit = Date.now() + hours * 3600_000;
  const licenseLimit = license.expires_at ? new Date(license.expires_at).getTime() : Number.POSITIVE_INFINITY;
  const expiresAt = new Date(Math.min(leaseLimit, licenseLimit)).toISOString();
  const lease: JsonObject = {
    version: 1,
    licenseId: license.id,
    deviceId,
    edition: license.edition,
    features: ["clean", "scan", "optimize"],
    issuedAt: nowIso(),
    expiresAt,
    licenseExpiresAt: license.expires_at,
    nonce: uuid(),
  };
  await audit(env, req, "LICENSE_VALIDATED", null, license.id, deviceId);
  return json({ success: true, lease, signature: await sign(env, lease), canonicalBaseUrl: await canonicalBaseUrl(req, env) });
}

async function activate(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("cf-connecting-ip") || "unknown";
  if (!await rateLimit(env, `activate:${ip}`, 10, 60)) return fail("RATE_LIMITED", "请求过于频繁", 429);
  const body = await readJson(req);
  const key = String(body.licenseKey || "").trim();
  const deviceId = String(body.deviceId || "").trim();
  if (!key || !deviceId || deviceId.length > 200) return fail("INVALID_REQUEST", "缺少或无效的授权码/设备标识");

  let license = await loadLicense(env, key);
  if (!license) {
    await audit(env, req, "LICENSE_REJECTED", { code: "LICENSE_NOT_FOUND" });
    return fail("LICENSE_NOT_FOUND", "授权码不存在", 404);
  }
  const licenseError = checkLicenseUsable(license);
  if (licenseError) return licenseError;

  const existing = await env.DB.prepare("SELECT id,license_id,device_id,public_key,device_name,windows_version,app_version,revoked_at FROM devices WHERE license_id=? AND device_id=?")
    .bind(license.id, deviceId).first<DeviceRow>();

  if (!existing || existing.revoked_at) {
    const count = await env.DB.prepare("SELECT COUNT(*) c FROM devices WHERE license_id=? AND revoked_at IS NULL").bind(license.id).first<{ c: number }>();
    if ((count?.c || 0) >= license.max_devices) return fail("DEVICE_LIMIT_REACHED", "已达到设备数量限制", 409);

    let effectiveExpiry = license.expires_at;
    if (!license.activated_at && license.license_type === "duration" && license.duration_days) {
      effectiveExpiry = new Date(Date.now() + Number(license.duration_days) * 86400000).toISOString();
    }
    const time = nowIso();
    if (existing) {
      await env.DB.batch([
        env.DB.prepare("UPDATE devices SET public_key=?,device_name=?,windows_version=?,app_version=?,first_seen_at=?,last_seen_at=?,revoked_at=NULL WHERE id=?")
          .bind(body.devicePublicKey || existing.public_key, body.deviceName || existing.device_name, body.windowsVersion || existing.windows_version, body.appVersion || existing.app_version, time, time, existing.id),
        env.DB.prepare("UPDATE licenses SET activated_at=COALESCE(activated_at,?),expires_at=COALESCE(?,expires_at),updated_at=? WHERE id=?")
          .bind(time, effectiveExpiry, time, license.id),
      ]);
      await audit(env, req, "DEVICE_REBOUND", { deviceName: body.deviceName || existing.device_name }, license.id, deviceId);
    } else {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO devices(id,license_id,device_id,public_key,device_name,windows_version,app_version,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?)")
          .bind(uuid(), license.id, deviceId, body.devicePublicKey || null, body.deviceName || null, body.windowsVersion || null, body.appVersion || null, time, time),
        env.DB.prepare("UPDATE licenses SET activated_at=COALESCE(activated_at,?),expires_at=COALESCE(?,expires_at),updated_at=? WHERE id=?")
          .bind(time, effectiveExpiry, time, license.id),
      ]);
      await audit(env, req, "DEVICE_BOUND", { deviceName: body.deviceName || null }, license.id, deviceId);
    }
    license = { ...license, activated_at: license.activated_at || time, expires_at: effectiveExpiry };
  } else {
    await env.DB.prepare("UPDATE devices SET last_seen_at=?,app_version=?,windows_version=? WHERE id=?")
      .bind(nowIso(), body.appVersion || existing.app_version, body.windowsVersion || existing.windows_version, existing.id).run();
  }

  return issueLease(req, env, license, deviceId);
}

async function validateOrRefresh(req: Request, env: Env, mode: "validate" | "refresh"): Promise<Response> {
  const ip = req.headers.get("cf-connecting-ip") || "unknown";
  if (!await rateLimit(env, `${mode}:${ip}`, 60, 60)) return fail("RATE_LIMITED", "请求过于频繁", 429);
  const body = await readJson(req);
  const key = String(body.licenseKey || "").trim();
  const deviceId = String(body.deviceId || "").trim();
  if (!key || !deviceId) return fail("INVALID_REQUEST", "缺少授权码或设备标识");
  const license = await loadLicense(env, key);
  if (!license) return fail("LICENSE_NOT_FOUND", "授权码不存在", 404);
  const licenseError = checkLicenseUsable(license);
  if (licenseError) return licenseError;
  const device = await env.DB.prepare("SELECT id FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL")
    .bind(license.id, deviceId).first<{ id: string }>();
  if (!device) return fail("DEVICE_NOT_BOUND", "设备未绑定或已解绑，请重新激活", 403);
  await env.DB.prepare("UPDATE devices SET last_seen_at=?,app_version=COALESCE(?,app_version),windows_version=COALESCE(?,windows_version) WHERE id=?")
    .bind(nowIso(), body.appVersion || null, body.windowsVersion || null, device.id).run();
  return issueLease(req, env, license, deviceId);
}

async function challenge(req: Request, env: Env): Promise<Response> {
  const body = await readJson(req);
  const deviceId = String(body.deviceId || "").trim();
  if (!deviceId) return fail("INVALID_REQUEST", "缺少设备标识");
  const active = await env.DB.prepare("SELECT id FROM devices WHERE device_id=? AND revoked_at IS NULL LIMIT 1").bind(deviceId).first();
  if (!active) return fail("DEVICE_NOT_BOUND", "设备未绑定", 404);
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const nonce = b64url(bytes);
  const expiresAt = new Date(Date.now() + 300000).toISOString();
  await env.DB.prepare("DELETE FROM device_challenges WHERE expires_at < ? OR used_at IS NOT NULL").bind(nowIso()).run();
  await env.DB.prepare("INSERT INTO device_challenges(id,device_id,nonce,expires_at,created_at) VALUES(?,?,?,?,?)")
    .bind(uuid(), deviceId, nonce, expiresAt, nowIso()).run();
  return json({ success: true, nonce, expiresAt });
}

async function verifyDevice(req: Request, env: Env): Promise<Response> {
  const body = await readJson(req);
  const deviceId = String(body.deviceId || "").trim();
  const nonce = String(body.nonce || "").trim();
  const signature = String(body.signature || "").trim();
  if (!deviceId || !nonce || !signature) return fail("INVALID_REQUEST", "缺少设备验证参数");
  const device = await env.DB.prepare("SELECT public_key FROM devices WHERE device_id=? AND revoked_at IS NULL ORDER BY last_seen_at DESC LIMIT 1")
    .bind(deviceId).first<{ public_key: string | null }>();
  const challengeRow = await env.DB.prepare("SELECT id,expires_at FROM device_challenges WHERE device_id=? AND nonce=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1")
    .bind(deviceId, nonce).first<{ id: string; expires_at: string }>();
  if (!device?.public_key || !challengeRow || new Date(challengeRow.expires_at).getTime() <= Date.now()) return fail("INVALID_DEVICE_SIGNATURE", "设备验证失败", 403);
  try {
    const raw = device.public_key.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, "");
    const publicKey = await crypto.subtle.importKey("spki", Uint8Array.from(atob(raw), c => c.charCodeAt(0)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, unb64url(signature), encoder.encode(nonce));
    if (!ok) return fail("INVALID_DEVICE_SIGNATURE", "设备签名验证失败", 403);
    await env.DB.prepare("UPDATE device_challenges SET used_at=? WHERE id=? AND used_at IS NULL").bind(nowIso(), challengeRow.id).run();
    return json({ success: true, verified: true });
  } catch {
    return fail("INVALID_DEVICE_SIGNATURE", "设备签名格式错误", 403);
  }
}

async function login(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("cf-connecting-ip") || "unknown";
  if (!await rateLimit(env, `login:${ip}`, 5, 60)) return fail("RATE_LIMITED", "登录尝试过多，请稍后再试", 429);
  const body = await readJson(req);
  const passwordOk = safeEqual(String(body.password || ""), env.ADMIN_PASSWORD || "");
  const turnstileOk = await verifyTurnstile(req, env, String(body.turnstileToken || ""));
  if (!passwordOk || !turnstileOk) {
    await audit(env, req, "ADMIN_LOGIN_FAILED", { passwordOk, turnstileOk });
    return fail("LOGIN_FAILED", "密码或验证码错误", 403);
  }
  await audit(env, req, "ADMIN_LOGIN_SUCCESS");
  return json({ success: true }, 200, {
    "set-cookie": `cleanc_session=${await createSession(env)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
  });
}

async function testCanonicalDomain(origin: string): Promise<boolean> {
  try {
    const response = await fetch(`${origin}/api/v1/health`, { headers: { "user-agent": "CleanC-License-Domain-Check/1.0" }, redirect: "error" });
    if (!response.ok) return false;
    const data = await response.json() as { status?: string };
    return data.status === "ok";
  } catch {
    return false;
  }
}

async function adminApi(req: Request, env: Env, path: string): Promise<Response> {
  const write = ["POST", "PUT", "PATCH", "DELETE"].includes(req.method);
  if (!await requireAdmin(req, env, write)) return fail(write ? "CSRF_OR_AUTH_FAILED" : "UNAUTHORIZED", "未授权", write ? 403 : 401);

  if (path === "/admin/api/session" && req.method === "GET") return json({ success: true, csrfToken: await csrfToken(req, env) });

  if (path === "/admin/api/dashboard" && req.method === "GET") {
    const licenses = await env.DB.prepare("SELECT COUNT(*) total,SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) active,SUM(CASE WHEN status='disabled' THEN 1 ELSE 0 END) disabled FROM licenses WHERE deleted_at IS NULL").first<any>();
    const devices = await env.DB.prepare("SELECT COUNT(*) c FROM devices WHERE revoked_at IS NULL").first<{ c: number }>();
    return json({ success: true, stats: { total: licenses?.total || 0, active: licenses?.active || 0, disabled: licenses?.disabled || 0, devices: devices?.c || 0 } });
  }

  if (path === "/admin/api/licenses" && req.method === "GET") {
    const { results } = await env.DB.prepare("SELECT l.*,(SELECT COUNT(*) FROM devices d WHERE d.license_id=l.id AND d.revoked_at IS NULL) device_count FROM licenses l WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 500").all();
    return json({ success: true, licenses: results });
  }

  if (path === "/admin/api/licenses" && req.method === "POST") {
    const body = await readJson(req);
    const count = positiveInt(body.count, 1, 1000);
    const maxDevices = positiveInt(body.maxDevices, 1, 1000);
    if (!count || !maxDevices) return fail("INVALID_NUMBER", "数量或设备上限格式不正确");
    const type = ["permanent", "duration", "fixed"].includes(String(body.licenseType)) ? String(body.licenseType) : "permanent";
    const durationDays = type === "duration" ? positiveInt(body.durationDays, 365, 36500) : null;
    if (type === "duration" && !durationDays) return fail("INVALID_DURATION", "有效天数必须为 1-36500 的整数");
    const expiresAt = type === "fixed" ? validDate(body.expiresAt) : null;
    if (type === "fixed" && (!expiresAt || new Date(expiresAt).getTime() <= Date.now())) return fail("INVALID_EXPIRES_AT", "固定到期时间必须是未来的有效时间");
    const customKey = String(body.licenseKey || "").trim();
    if (count > 1 && customKey) return fail("CUSTOM_KEY_BATCH_NOT_ALLOWED", "批量生成时不能指定单个自定义授权码");
    if (customKey && !validCustomLicenseKey(customKey)) return fail("INVALID_LICENSE_KEY", "自定义授权码仅允许 6-80 位字母、数字、下划线和短横线");

    const created: string[] = [];
    for (let i = 0; i < count; i++) {
      let key = customKey || randomLicenseKey();
      for (let retry = 0; retry < 5; retry++) {
        const exists = await env.DB.prepare("SELECT id FROM licenses WHERE license_key=?").bind(key).first();
        if (!exists) break;
        if (customKey) return fail("LICENSE_KEY_EXISTS", "授权码已存在", 409);
        key = randomLicenseKey();
        if (retry === 4) return fail("LICENSE_KEY_COLLISION", "生成授权码发生冲突，请重试", 500);
      }
      const licenseId = uuid();
      await env.DB.prepare("INSERT INTO licenses(id,license_key,edition,status,license_type,duration_days,expires_at,max_devices,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
        .bind(licenseId, key, String(body.edition || "pro"), "active", type, durationDays, expiresAt, maxDevices, body.note ? String(body.note).slice(0, 500) : null, nowIso(), nowIso()).run();
      created.push(key);
      await audit(env, req, count > 1 ? "LICENSE_BATCH_CREATED" : "LICENSE_CREATED", { licenseKey: key }, licenseId);
    }
    return json({ success: true, licenseKeys: created });
  }

  const licenseAction = path.match(/^\/admin\/api\/licenses\/([^/]+)\/(disable|enable)$/);
  if (licenseAction && req.method === "POST") {
    const status = licenseAction[2] === "disable" ? "disabled" : "active";
    const result = await env.DB.prepare("UPDATE licenses SET status=?,updated_at=? WHERE id=? AND deleted_at IS NULL").bind(status, nowIso(), licenseAction[1]).run();
    if (!result.meta.changes) return fail("LICENSE_NOT_FOUND", "授权不存在", 404);
    await audit(env, req, status === "disabled" ? "LICENSE_DISABLED" : "LICENSE_ENABLED", null, licenseAction[1]);
    return json({ success: true });
  }

  if (path === "/admin/api/devices" && req.method === "GET") {
    const { results } = await env.DB.prepare("SELECT d.*,l.license_key FROM devices d JOIN licenses l ON l.id=d.license_id ORDER BY d.last_seen_at DESC LIMIT 500").all();
    return json({ success: true, devices: results });
  }

  const deviceRevoke = path.match(/^\/admin\/api\/devices\/([^/]+)\/revoke$/);
  if (deviceRevoke && req.method === "POST") {
    const result = await env.DB.prepare("UPDATE devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL").bind(nowIso(), deviceRevoke[1]).run();
    if (!result.meta.changes) return fail("DEVICE_NOT_FOUND", "设备不存在或已解绑", 404);
    await audit(env, req, "DEVICE_REVOKED", { id: deviceRevoke[1] });
    return json({ success: true });
  }

  if (path === "/admin/api/logs" && req.method === "GET") {
    const { results } = await env.DB.prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500").all();
    return json({ success: true, logs: results });
  }

  if (path === "/admin/api/settings" && req.method === "GET") {
    return json({
      success: true,
      currentOrigin: new URL(req.url).origin,
      bootstrapBaseUrl: configuredBootstrapUrl(req, env),
      canonicalBaseUrl: await canonicalBaseUrl(req, env),
      turnstileSiteKey: env.TURNSTILE_SITE_KEY || "",
    });
  }

  if (path === "/admin/api/settings/domain" && req.method === "POST") {
    const body = await readJson(req);
    if (!safeEqual(String(body.password || ""), env.ADMIN_PASSWORD || "") || !await verifyTurnstile(req, env, String(body.turnstileToken || ""))) return fail("REAUTH_FAILED", "二次验证失败", 403);
    const next = normalizeHttpsOrigin(String(body.baseUrl || ""));
    if (!next) return fail("INVALID_DOMAIN", "域名格式不正确，只允许公网 HTTPS 域名", 400);
    if (!await testCanonicalDomain(next)) return fail("DOMAIN_NOT_READY", "域名尚未正确绑定到此 Worker，或 /api/v1/health 无法访问", 400);
    const old = await getSetting(env, "PRIMARY_BASE_URL");
    await env.DB.batch([
      env.DB.prepare("INSERT INTO system_settings(setting_key,setting_value,updated_at) VALUES('PRIMARY_BASE_URL',?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at").bind(next, nowIso()),
      env.DB.prepare("INSERT INTO domain_history(id,old_url,new_url,ip,created_at) VALUES(?,?,?,?,?)").bind(uuid(), old, next, req.headers.get("cf-connecting-ip"), nowIso()),
    ]);
    await audit(env, req, "DOMAIN_CHANGED", { old, next });
    return json({ success: true, canonicalBaseUrl: next });
  }

  if (path === "/admin/api/settings/domain/rollback" && req.method === "POST") {
    const body = await readJson(req);
    if (!safeEqual(String(body.password || ""), env.ADMIN_PASSWORD || "") || !await verifyTurnstile(req, env, String(body.turnstileToken || ""))) return fail("REAUTH_FAILED", "二次验证失败", 403);
    const old = await getSetting(env, "PRIMARY_BASE_URL");
    const fallback = configuredBootstrapUrl(req, env);
    await env.DB.prepare("DELETE FROM system_settings WHERE setting_key='PRIMARY_BASE_URL'").run();
    await audit(env, req, "DOMAIN_ROLLBACK", { old, next: fallback });
    return json({ success: true, canonicalBaseUrl: fallback });
  }

  return fail("NOT_FOUND", "接口不存在", 404);
}

function adminPage(env: Env): string {
  const siteKey = (env.TURNSTILE_SITE_KEY || "").replace(/"/g, "&quot;");
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CleanC License Server</title><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#12213c;background:radial-gradient(circle at 10% 10%,#cfe9ff,transparent 36%),radial-gradient(circle at 90% 5%,#eadcff,transparent 36%),linear-gradient(135deg,#f8fbff,#eef4ff);min-height:100vh}.glass{background:rgba(255,255,255,.62);backdrop-filter:blur(28px) saturate(150%);border:1px solid rgba(255,255,255,.82);box-shadow:0 24px 70px rgba(43,72,140,.14),inset 0 1px 0 #fff;border-radius:28px}.login{width:min(420px,calc(100% - 32px));padding:34px;position:absolute;left:50%;top:50%;transform:translate(-50%,-50%)}.logo{width:56px;height:56px;border-radius:18px;display:grid;place-items:center;font-size:26px;font-weight:800;color:#fff;background:linear-gradient(145deg,#4a8cff,#765cff)}.muted{color:#708099}input,select,button{font:inherit}input,select{width:100%;padding:12px 14px;border:1px solid #dce5f4;border-radius:14px;background:#ffffffd9}.btn{border:0;border-radius:14px;padding:11px 15px;cursor:pointer;font-weight:650}.primary{background:linear-gradient(135deg,#4d88ff,#735cff);color:#fff}.danger{background:#fff0f2;color:#c73555}.app{display:none;min-height:100vh;padding:20px}.side{position:fixed;top:20px;bottom:20px;width:230px;padding:22px}.nav button{display:block;width:100%;text-align:left;margin:7px 0;background:transparent;color:#58667e}.nav button.active{background:#ffffffcf;color:#315fc5}.main{margin-left:250px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card,.panel{padding:20px}.panel{margin-top:16px}.stat b{font-size:30px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row>*{flex:1}.row .btn{flex:0 0 auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #e4eaf3}code{background:#eef3ff;padding:3px 6px;border-radius:7px;word-break:break-all}.section{display:none}.section.active{display:block}.hidden{display:none!important}.notice{padding:12px 14px;border-radius:14px;background:#fff8dd;color:#7a5a00;margin:12px 0}@media(max-width:850px){.side{position:static;width:auto;margin-bottom:14px}.main{margin-left:0}.grid{grid-template-columns:repeat(2,1fr)}.app{padding:12px}}
</style></head><body>
<div id="login" class="login glass"><div class="logo">C</div><h1>CleanC License</h1><p class="muted">管理员控制台</p><input id="password" type="password" autocomplete="current-password" placeholder="管理员密码"><div style="height:14px"></div><div id="loginTs" class="cf-turnstile" data-sitekey="${siteKey}"></div><div style="height:14px"></div><button class="btn primary" style="width:100%" onclick="doLogin()">登录</button><p id="loginMsg" class="muted"></p></div>
<div id="app" class="app"><aside class="side glass"><div class="row"><div class="logo" style="width:42px;height:42px;font-size:20px">C</div><b>CleanC</b></div><div class="nav" style="margin-top:22px"><button class="btn active" data-tab="dashboard">仪表盘</button><button class="btn" data-tab="licenses">授权管理</button><button class="btn" data-tab="devices">设备管理</button><button class="btn" data-tab="logs">操作日志</button><button class="btn" data-tab="settings">设置</button></div></aside>
<main class="main"><h2 id="title">仪表盘</h2><p class="muted">CleanC 授权服务管理中心</p>
<section id="dashboard" class="section active"><div class="grid"><div class="card glass stat">总授权<br><b id="sTotal">-</b></div><div class="card glass stat">有效授权<br><b id="sActive">-</b></div><div class="card glass stat">已禁用<br><b id="sDisabled">-</b></div><div class="card glass stat">绑定设备<br><b id="sDevices">-</b></div></div></section>
<section id="licenses" class="section"><div class="panel glass"><div class="row"><input id="customKey" placeholder="自定义授权码（留空随机）"><select id="licenseType" onchange="licenseTypeChanged()"><option value="permanent">永久</option><option value="duration">激活后 N 天</option><option value="fixed">固定到期</option></select><input id="durationDays" type="number" value="365" min="1" max="36500" placeholder="有效天数"><input id="expiresAt" class="hidden" type="datetime-local"><input id="maxDevices" type="number" value="1" min="1" max="1000" placeholder="设备数"><input id="batchCount" type="number" value="1" min="1" max="1000" placeholder="生成数量"><button class="btn primary" onclick="createLicense()">生成授权</button></div><div style="height:10px"></div><input id="licenseNote" placeholder="备注（可选）"></div><div class="panel glass" style="overflow:auto"><table><thead><tr><th>授权码</th><th>状态</th><th>类型</th><th>到期</th><th>设备</th><th>创建</th><th>操作</th></tr></thead><tbody id="licenseRows"></tbody></table></div></section>
<section id="devices" class="section"><div class="panel glass" style="overflow:auto"><table><thead><tr><th>设备</th><th>授权码</th><th>Windows</th><th>App</th><th>最近在线</th><th>状态</th><th>操作</th></tr></thead><tbody id="deviceRows"></tbody></table></div></section>
<section id="logs" class="section"><div class="panel glass" style="overflow:auto"><table><thead><tr><th>时间</th><th>事件</th><th>IP</th><th>详情</th></tr></thead><tbody id="logRows"></tbody></table></div></section>
<section id="settings" class="section"><div class="panel glass"><h3>域名与 API</h3><p>当前访问：<code id="currentOrigin">-</code></p><p>Bootstrap：<code id="bootstrapUrl">-</code></p><p>主授权地址：<code id="canonicalUrl">-</code></p><div class="notice">先在 Cloudflare 给 Worker 绑定自定义域名，并把域名加入 Turnstile Hostname Management，再在这里保存。系统会先检测新域名的 /api/v1/health。</div><div class="row"><input id="newDomain" placeholder="license.example.com"><input id="confirmPassword" type="password" placeholder="管理员密码"></div><div style="height:12px"></div><div id="settingsTs" class="cf-turnstile" data-sitekey="${siteKey}"></div><div style="height:12px"></div><button class="btn primary" onclick="saveDomain()">检测并保存</button> <button class="btn danger" onclick="rollbackDomain()">恢复 Bootstrap 地址</button></div><div class="panel glass"><h3>API 信息</h3><div id="apiList"></div></div></section>
</main></div>
<script>
var csrf='';function q(id){return document.getElementById(id)}function esc(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
async function call(path,opt){opt=opt||{};opt.headers=Object.assign({},opt.headers||{}, {'content-type':'application/json','x-csrf-token':csrf});var r=await fetch(path,opt);var j;try{j=await r.json()}catch(e){j={success:false,message:'服务器返回格式异常'}}if(!r.ok&&j.success!==false)j.success=false;return j}
async function boot(){var r=await fetch('/admin/api/session',{cache:'no-store'});if(!r.ok)return;var j=await r.json();csrf=j.csrfToken;q('login').style.display='none';q('app').style.display='block';loadDashboard()}
async function doLogin(){var token=q('loginTs').querySelector('[name="cf-turnstile-response"]')?.value||'';var r=await call('/admin/api/login',{method:'POST',body:JSON.stringify({password:q('password').value,turnstileToken:token})});if(r.success)location.reload();else{q('loginMsg').textContent=r.message||'登录失败';if(window.turnstile)turnstile.reset(q('loginTs'))}}
async function loadDashboard(){var r=await call('/admin/api/dashboard');if(r.success){q('sTotal').textContent=r.stats.total;q('sActive').textContent=r.stats.active;q('sDisabled').textContent=r.stats.disabled;q('sDevices').textContent=r.stats.devices}}
function licenseTypeChanged(){var t=q('licenseType').value;q('durationDays').classList.toggle('hidden',t!=='duration');q('expiresAt').classList.toggle('hidden',t!=='fixed')}
async function loadLicenses(){var r=await call('/admin/api/licenses');q('licenseRows').innerHTML=(r.licenses||[]).map(function(x){return '<tr><td><code>'+esc(x.license_key)+'</code></td><td>'+esc(x.status)+'</td><td>'+esc(x.license_type)+'</td><td>'+esc(x.expires_at||'-')+'</td><td>'+x.device_count+'/'+x.max_devices+'</td><td>'+esc((x.created_at||'').slice(0,10))+'</td><td><button class="btn" onclick="toggleLic(\''+x.id+'\',\''+(x.status==='active'?'disable':'enable')+'\')">'+(x.status==='active'?'禁用':'恢复')+'</button></td></tr>'}).join('')}
async function createLicense(){var fixed=q('expiresAt').value;var r=await call('/admin/api/licenses',{method:'POST',body:JSON.stringify({licenseKey:q('customKey').value,licenseType:q('licenseType').value,durationDays:+q('durationDays').value,expiresAt:fixed?new Date(fixed).toISOString():null,maxDevices:+q('maxDevices').value,count:+q('batchCount').value,note:q('licenseNote').value})});if(r.success){alert('已生成 '+r.licenseKeys.length+' 个授权码\n'+r.licenseKeys.slice(0,30).join('\n'));loadLicenses();loadDashboard()}else alert(r.message||r.code||'生成失败')}
async function toggleLic(i,o){var r=await call('/admin/api/licenses/'+i+'/'+o,{method:'POST',body:'{}'});if(!r.success)alert(r.message||'操作失败');loadLicenses();loadDashboard()}
async function loadDevices(){var r=await call('/admin/api/devices');q('deviceRows').innerHTML=(r.devices||[]).map(function(x){return '<tr><td>'+esc(x.device_name||x.device_id)+'</td><td><code>'+esc(x.license_key)+'</code></td><td>'+esc(x.windows_version)+'</td><td>'+esc(x.app_version)+'</td><td>'+esc(x.last_seen_at)+'</td><td>'+(x.revoked_at?'已解绑':'已绑定')+'</td><td>'+(x.revoked_at?'-':'<button class="btn danger" onclick="revokeDevice(\''+x.id+'\')">解绑</button>')+'</td></tr>'}).join('')}
async function revokeDevice(i){if(confirm('确认解绑此设备？解绑后会释放设备名额；设备以后可再次激活。')){var r=await call('/admin/api/devices/'+i+'/revoke',{method:'POST',body:'{}'});if(!r.success)alert(r.message||'解绑失败');loadDevices();loadDashboard()}}
async function loadLogs(){var r=await call('/admin/api/logs');q('logRows').innerHTML=(r.logs||[]).map(function(x){return '<tr><td>'+esc(x.created_at)+'</td><td>'+esc(x.event_type)+'</td><td>'+esc(x.ip)+'</td><td><code>'+esc(x.detail)+'</code></td></tr>'}).join('')}
async function loadSettings(){var r=await call('/admin/api/settings');if(!r.success)return;q('currentOrigin').textContent=r.currentOrigin;q('canonicalUrl').textContent=r.canonicalBaseUrl;q('bootstrapUrl').textContent=r.bootstrapBaseUrl+'/bootstrap/v1/config';var e=['/api/v1/license/activate','/api/v1/license/validate','/api/v1/license/refresh','/api/v1/device/challenge','/api/v1/device/verify','/api/v1/health','/api/v1/meta'];q('apiList').innerHTML=e.map(function(x){return '<p><code>'+esc(r.canonicalBaseUrl+x)+'</code></p>'}).join('')}
function settingsToken(){return q('settingsTs').querySelector('[name="cf-turnstile-response"]')?.value||''}
async function saveDomain(){var r=await call('/admin/api/settings/domain',{method:'POST',body:JSON.stringify({baseUrl:q('newDomain').value,password:q('confirmPassword').value,turnstileToken:settingsToken()})});alert(r.success?'主授权域名已更新':(r.message||r.code||'保存失败'));if(r.success)loadSettings();if(window.turnstile)turnstile.reset(q('settingsTs'))}
async function rollbackDomain(){var r=await call('/admin/api/settings/domain/rollback',{method:'POST',body:JSON.stringify({password:q('confirmPassword').value,turnstileToken:settingsToken()})});alert(r.success?'已恢复 Bootstrap 地址':(r.message||'验证失败'));if(r.success)loadSettings();if(window.turnstile)turnstile.reset(q('settingsTs'))}
document.querySelectorAll('.nav button').forEach(function(b){b.onclick=async function(){document.querySelectorAll('.nav button').forEach(function(x){x.classList.remove('active')});document.querySelectorAll('.section').forEach(function(x){x.classList.remove('active')});b.classList.add('active');q(b.dataset.tab).classList.add('active');q('title').textContent=b.textContent;if(b.dataset.tab==='dashboard')loadDashboard();if(b.dataset.tab==='licenses')loadLicenses();if(b.dataset.tab==='devices')loadDevices();if(b.dataset.tab==='logs')loadLogs();if(b.dataset.tab==='settings')loadSettings()}});licenseTypeChanged();boot();
</script></body></html>`;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      if (path === "/api/v1/health" && req.method === "GET") return json({ status: "ok", apiVersion: 1 });
      if (path === "/api/v1/meta" && req.method === "GET") return json({ appName: env.APP_NAME || "CleanC", apiVersion: 1, canonicalBaseUrl: await canonicalBaseUrl(req, env) });
      if (path === "/bootstrap/v1/config" && req.method === "GET") {
        const payload: JsonObject = { apiVersion: 1, canonicalBaseUrl: await canonicalBaseUrl(req, env), issuedAt: nowIso() };
        return json({ ...payload, signature: await sign(env, payload) });
      }
      if (path === "/api/v1/license/activate" && req.method === "POST") return activate(req, env);
      if (path === "/api/v1/license/validate" && req.method === "POST") return validateOrRefresh(req, env, "validate");
      if (path === "/api/v1/license/refresh" && req.method === "POST") return validateOrRefresh(req, env, "refresh");
      if (path === "/api/v1/device/challenge" && req.method === "POST") return challenge(req, env);
      if (path === "/api/v1/device/verify" && req.method === "POST") return verifyDevice(req, env);
      if (path === "/admin/api/login" && req.method === "POST") return login(req, env);
      if (path.startsWith("/admin/api/")) return adminApi(req, env, path);
      if (path === "/admin" || path === "/admin/" || path === "/admin/login") return html(adminPage(env));
      if (path === "/") return Response.redirect(new URL("/admin", req.url).toString(), 302);
      return fail("NOT_FOUND", "资源不存在", 404);
    } catch (error) {
      console.error(error);
      if (error instanceof Error && error.message === "INVALID_CONTENT_TYPE") return fail("INVALID_CONTENT_TYPE", "请求必须使用 application/json", 415);
      return fail("SERVER_ERROR", "服务器内部错误", 500);
    }
  },
};
