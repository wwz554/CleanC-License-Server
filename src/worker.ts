import { effectiveStatusSql } from './license-status';
import { adminPage } from './admin';

export interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  SESSION_SECRET: string;
  DEVICE_PROOF_SECRET: string;
  TURNSTILE_SECRET: string;
  LICENSE_SIGNING_PRIVATE_KEY: string;
  OFFLINE_RSA_PRIVATE_KEY?: string;
  APP_NAME?: string;
  TURNSTILE_SITE_KEY?: string;
  LEASE_HOURS?: string;
  BOOTSTRAP_BASE_URL?: string;
}

type JsonObject = Record<string, unknown>;
type LicenseRow = {
  id: string; license_key: string; edition: string; status: string; license_type: string;
  duration_days: number | null; expires_at: string | null; activated_at: string | null; max_devices: number;
};
type DeviceRow = {
  id: string; license_id: string; device_id: string; public_key: string | null; device_name: string | null;
  windows_version: string | null; app_version: string | null; revoked_at: string | null;
};
type ProofPayload = { licenseId: string; deviceId: string; exp: number; nonce: string };

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const nowIso = () => new Date().toISOString();
const uuid = () => crypto.randomUUID();

function b64url(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function unb64url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
function safeEqual(a: string, b: string): boolean {
  const x = encoder.encode(a), y = encoder.encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
function baseHeaders(): HeadersInit {
  return {
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
  };
}
function json(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...baseHeaders(), ...headers } });
}
function fail(code: string, message: string, status = 400): Response { return json({ success: false, code, message }, status); }
function html(body: string, status = 200): Response {
  return new Response(body, { status, headers: {
    'content-type': 'text/html; charset=utf-8', ...baseHeaders(),
    'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://challenges.cloudflare.com; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  }});
}
async function readJson(req: Request): Promise<Record<string, any>> {
  if (!(req.headers.get('content-type') || '').toLowerCase().includes('application/json')) throw new Error('INVALID_CONTENT_TYPE');
  return await req.json() as Record<string, any>;
}
async function hmac(secret: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, encoder.encode(text)));
}
async function createSession(env: Env): Promise<string> {
  const payload = b64url(encoder.encode(JSON.stringify({ exp: Date.now() + 8 * 3600_000, nonce: uuid() })));
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}
function getCookie(req: Request, name: string): string {
  return (req.headers.get('cookie') || '').split(/;\s*/).find(v => v.startsWith(name + '='))?.slice(name.length + 1) || '';
}
async function validSession(req: Request, env: Env): Promise<boolean> {
  const [payload, signature] = getCookie(req, 'cleanc_session').split('.');
  if (!payload || !signature || !safeEqual(signature, await hmac(env.SESSION_SECRET, payload))) return false;
  try {
    const parsed = JSON.parse(decoder.decode(unb64url(payload))) as { exp?: number };
    return typeof parsed.exp === 'number' && parsed.exp > Date.now();
  } catch { return false; }
}
async function csrfToken(req: Request, env: Env): Promise<string> { return hmac(env.SESSION_SECRET, `csrf:${getCookie(req, 'cleanc_session')}`); }
async function requireAdmin(req: Request, env: Env, write = false): Promise<boolean> {
  if (!await validSession(req, env)) return false;
  return !write || safeEqual(req.headers.get('x-csrf-token') || '', await csrfToken(req, env));
}
async function audit(env: Env, req: Request, eventType: string, detail: unknown = null, licenseId: string | null = null, deviceId: string | null = null): Promise<void> {
  await env.DB.prepare('INSERT INTO audit_logs(id,event_type,ip,license_id,device_id,detail,created_at) VALUES(?,?,?,?,?,?,?)')
    .bind(uuid(), eventType, req.headers.get('cf-connecting-ip'), licenseId, deviceId, detail == null ? null : JSON.stringify(detail), nowIso()).run();
}
async function rateLimit(env: Env, key: string, max: number, seconds: number): Promise<boolean> {
  const current = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(`INSERT INTO rate_limits(bucket_key,count,window_start) VALUES(?,1,?)
    ON CONFLICT(bucket_key) DO UPDATE SET
      count=CASE WHEN ?-window_start>=? THEN 1 ELSE count+1 END,
      window_start=CASE WHEN ?-window_start>=? THEN ? ELSE window_start END
    RETURNING count,window_start`)
    .bind(key, current, current, seconds, current, seconds, current).first<{ count: number; window_start: number }>();
  return !!row && row.count <= max;
}
async function verifyTurnstile(req: Request, env: Env, token: string): Promise<boolean> {
  if (!env.TURNSTILE_SECRET || !token) return false;
  const form = new FormData();
  form.set('secret', env.TURNSTILE_SECRET); form.set('response', token);
  const ip = req.headers.get('cf-connecting-ip'); if (ip) form.set('remoteip', ip);
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
    const result = await r.json() as { success?: boolean; hostname?: string };
    return result.success === true && result.hostname === new URL(req.url).hostname;
  } catch { return false; }
}
async function getSetting(env: Env, key: string): Promise<string | null> {
  return (await env.DB.prepare('SELECT setting_value FROM system_settings WHERE setting_key=?').bind(key).first<{ setting_value: string }>())?.setting_value || null;
}
function configuredBootstrapUrl(req: Request, env: Env): string {
  const configured = String(env.BOOTSTRAP_BASE_URL || '').trim().replace(/\/$/, '');
  return configured || new URL(req.url).origin;
}
async function canonicalBaseUrl(req: Request, env: Env): Promise<string> { return (await getSetting(env, 'PRIMARY_BASE_URL')) || configuredBootstrapUrl(req, env); }
function normalizeHttpsOrigin(input: string): string | null {
  try {
    const url = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
    const host = url.hostname.toLowerCase();
    const privateHost = host === 'localhost' || host === '::1' || /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host);
    if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash || privateHost) return null;
    return `https://${host}${url.port ? `:${url.port}` : ''}`;
  } catch { return null; }
}
async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const raw = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+/g, '');
  if (!raw) throw new Error('SIGNING_KEY_MISSING');
  return crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(raw), c => c.charCodeAt(0)), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}
async function validatePublicKeyPem(pem: string): Promise<boolean> {
  try {
    const raw = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
    if (!raw) return false;
    await crypto.subtle.importKey('spki', Uint8Array.from(atob(raw), c => c.charCodeAt(0)), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return true;
  } catch { return false; }
}
async function signObject(env: Env, object: JsonObject): Promise<{ signedPayload: string; signature: string }> {
  const serialized = JSON.stringify(object);
  const key = await importPrivateKey(env.LICENSE_SIGNING_PRIVATE_KEY);
  const signature = b64url(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, encoder.encode(serialized)));
  return { signedPayload: b64url(encoder.encode(serialized)), signature };
}
function randomLicenseKey(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  while (out.length < 16) {
    const bytes = new Uint8Array(32); crypto.getRandomValues(bytes);
    for (const b of bytes) {
      if (b >= 224) continue;
      out += chars[b % chars.length];
      if (out.length === 16) break;
    }
  }
  return `CLC-${out.slice(0,4)}-${out.slice(4,8)}-${out.slice(8,12)}-${out.slice(12,16)}`;
}
function validCustomLicenseKey(value: string): boolean { return /^[A-Za-z0-9_-]{6,80}$/.test(value); }
function positiveInt(value: unknown, fallback: number, max: number): number | null {
  const n = Number(value ?? fallback); return Number.isInteger(n) && n >= 1 && n <= max ? n : null;
}
function validDate(value: unknown): string | null {
  if (!value) return null; const d = new Date(String(value)); return Number.isFinite(d.getTime()) ? d.toISOString() : null;
}
async function loadLicense(env: Env, key: string): Promise<LicenseRow | null> {
  return env.DB.prepare('SELECT id,license_key,edition,status,license_type,duration_days,expires_at,activated_at,max_devices FROM licenses WHERE license_key=? AND deleted_at IS NULL').bind(key).first<LicenseRow>();
}
function checkLicenseUsable(license: LicenseRow): Response | null {
  if (license.status.toLowerCase() !== 'active') return fail('LICENSE_DISABLED', '授权不可用', 403);
  if (license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) return fail('LICENSE_EXPIRED', '授权已过期', 403);
  return null;
}
async function issueDeviceProof(env: Env, licenseId: string, deviceId: string): Promise<string> {
  const payload: ProofPayload = { licenseId, deviceId, exp: Date.now() + 10 * 60_000, nonce: uuid() };
  const encoded = b64url(encoder.encode(JSON.stringify(payload)));
  return `${encoded}.${await hmac(env.DEVICE_PROOF_SECRET, encoded)}`;
}
async function validDeviceProof(env: Env, proof: string, licenseId: string, deviceId: string): Promise<boolean> {
  const [payload, signature] = proof.split('.');
  if (!payload || !signature || !safeEqual(signature, await hmac(env.DEVICE_PROOF_SECRET, payload))) return false;
  try {
    const p = JSON.parse(decoder.decode(unb64url(payload))) as ProofPayload;
    return p.licenseId === licenseId && p.deviceId === deviceId && p.exp > Date.now();
  } catch { return false; }
}
async function issueLease(req: Request, env: Env, license: LicenseRow, deviceId: string): Promise<Response> {
  const h = Number(env.LEASE_HOURS || 72); const hours = Number.isFinite(h) ? Math.max(1, Math.min(h, 720)) : 72;
  const leaseLimit = Date.now() + hours * 3600_000;
  const licenseLimit = license.expires_at ? new Date(license.expires_at).getTime() : Number.POSITIVE_INFINITY;
  const lease: JsonObject = { version: 2, licenseId: license.id, deviceId, edition: license.edition, features: ['clean','scan','optimize'], issuedAt: nowIso(), expiresAt: new Date(Math.min(leaseLimit, licenseLimit)).toISOString(), licenseExpiresAt: license.expires_at, nonce: uuid() };
  const signed = await signObject(env, lease);
  await audit(env, req, 'LICENSE_VALIDATED', null, license.id, deviceId);
  return json({ success: true, lease, ...signed, canonicalBaseUrl: await canonicalBaseUrl(req, env) });
}
async function activate(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(env, `activate:${ip}`, 10, 60)) return fail('RATE_LIMITED', '请求过于频繁', 429);
  const body = await readJson(req); const key = String(body.licenseKey || '').trim(); const deviceId = String(body.deviceId || '').trim(); const publicKey = String(body.devicePublicKey || '').trim();
  if (!key || !deviceId || deviceId.length > 200 || publicKey.length > 4000 || !await validatePublicKeyPem(publicKey)) return fail('INVALID_REQUEST', '授权码、设备标识或设备公钥无效');
  let license = await loadLicense(env, key); if (!license) { await audit(env, req, 'LICENSE_REJECTED', { code: 'LICENSE_NOT_FOUND' }); return fail('LICENSE_NOT_FOUND', '授权码不存在', 404); }
  const unusable = checkLicenseUsable(license); if (unusable) return unusable;
  const existing = await env.DB.prepare('SELECT id,license_id,device_id,public_key,device_name,windows_version,app_version,revoked_at FROM devices WHERE license_id=? AND device_id=?').bind(license.id, deviceId).first<DeviceRow>();
  const time = nowIso();
  if (!existing || existing.revoked_at) {
    const count = await env.DB.prepare('SELECT COUNT(*) c FROM devices WHERE license_id=? AND revoked_at IS NULL').bind(license.id).first<{ c: number }>();
    if ((count?.c || 0) >= license.max_devices) return fail('DEVICE_LIMIT_REACHED', '已达到设备数量限制', 409);
    let effectiveExpiry = license.expires_at;
    if (!license.activated_at && license.license_type === 'duration' && license.duration_days) effectiveExpiry = new Date(Date.now() + license.duration_days * 86400000).toISOString();
    if (existing) {
      await env.DB.batch([
        env.DB.prepare('UPDATE devices SET public_key=?,device_name=?,windows_version=?,app_version=?,first_seen_at=?,last_seen_at=?,revoked_at=NULL WHERE id=?').bind(publicKey, body.deviceName || existing.device_name, body.windowsVersion || existing.windows_version, body.appVersion || existing.app_version, time, time, existing.id),
        env.DB.prepare('UPDATE licenses SET activated_at=COALESCE(activated_at,?),expires_at=COALESCE(?,expires_at),updated_at=? WHERE id=?').bind(time, effectiveExpiry, time, license.id),
      ]);
      await audit(env, req, 'DEVICE_REBOUND', null, license.id, deviceId);
    } else {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO devices(id,license_id,device_id,public_key,device_name,windows_version,app_version,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?)').bind(uuid(), license.id, deviceId, publicKey, body.deviceName || null, body.windowsVersion || null, body.appVersion || null, time, time),
        env.DB.prepare('UPDATE licenses SET activated_at=COALESCE(activated_at,?),expires_at=COALESCE(?,expires_at),updated_at=? WHERE id=?').bind(time, effectiveExpiry, time, license.id),
      ]);
      await audit(env, req, 'DEVICE_BOUND', null, license.id, deviceId);
    }
    license = { ...license, activated_at: license.activated_at || time, expires_at: effectiveExpiry };
  } else {
    if (!existing.public_key || existing.public_key !== publicKey) return fail('DEVICE_KEY_MISMATCH', '设备公钥与已绑定设备不一致', 403);
    await env.DB.prepare('UPDATE devices SET last_seen_at=?,app_version=COALESCE(?,app_version),windows_version=COALESCE(?,windows_version) WHERE id=?').bind(time, body.appVersion || null, body.windowsVersion || null, existing.id).run();
  }
  return issueLease(req, env, license, deviceId);
}
async function validateOrRefresh(req: Request, env: Env, mode: 'validate'|'refresh'): Promise<Response> {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown'; if (!await rateLimit(env, `${mode}:${ip}`, 60, 60)) return fail('RATE_LIMITED', '请求过于频繁', 429);
  const body = await readJson(req); const key = String(body.licenseKey || '').trim(); const deviceId = String(body.deviceId || '').trim(); const proof = String(body.deviceProof || '').trim();
  if (!key || !deviceId || !proof) return fail('INVALID_REQUEST', '缺少授权码、设备标识或设备证明');
  const license = await loadLicense(env, key); if (!license) return fail('LICENSE_NOT_FOUND', '授权码不存在', 404);
  const unusable = checkLicenseUsable(license); if (unusable) return unusable;
  const device = await env.DB.prepare('SELECT id FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL').bind(license.id, deviceId).first<{ id: string }>();
  if (!device) return fail('DEVICE_NOT_BOUND', '设备未绑定或已解绑，请重新激活', 403);
  if (!await validDeviceProof(env, proof, license.id, deviceId)) return fail('DEVICE_PROOF_REQUIRED', '设备证明无效或已过期，请重新执行 challenge/verify', 403);
  await env.DB.prepare('UPDATE devices SET last_seen_at=?,app_version=COALESCE(?,app_version),windows_version=COALESCE(?,windows_version) WHERE id=?').bind(nowIso(), body.appVersion || null, body.windowsVersion || null, device.id).run();
  return issueLease(req, env, license, deviceId);
}
async function challenge(req: Request, env: Env): Promise<Response> {
  const body = await readJson(req); const key = String(body.licenseKey || '').trim(); const deviceId = String(body.deviceId || '').trim();
  if (!key || !deviceId) return fail('INVALID_REQUEST', '缺少授权码或设备标识');
  const license = await loadLicense(env, key); if (!license) return fail('LICENSE_NOT_FOUND', '授权码不存在', 404);
  const unusable = checkLicenseUsable(license); if (unusable) return unusable;
  const active = await env.DB.prepare('SELECT id,public_key FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL').bind(license.id, deviceId).first<{ id: string; public_key: string | null }>();
  if (!active?.public_key) return fail('DEVICE_NOT_BOUND', '设备未绑定或没有设备公钥', 404);
  const bytes = new Uint8Array(32); crypto.getRandomValues(bytes); const nonce = b64url(bytes); const expiresAt = new Date(Date.now() + 300000).toISOString();
  await env.DB.prepare('DELETE FROM device_challenges WHERE expires_at < ? OR used_at IS NOT NULL').bind(nowIso()).run();
  await env.DB.prepare('INSERT INTO device_challenges(id,device_id,nonce,expires_at,used_at,created_at,license_id) VALUES(?,?,?,?,NULL,?,?)').bind(uuid(), deviceId, nonce, expiresAt, nowIso(), license.id).run();
  return json({ success: true, nonce, expiresAt });
}
async function verifyDevice(req: Request, env: Env): Promise<Response> {
  const body = await readJson(req); const key = String(body.licenseKey || '').trim(); const deviceId = String(body.deviceId || '').trim(); const nonce = String(body.nonce || '').trim(); const signature = String(body.signature || '').trim();
  if (!key || !deviceId || !nonce || !signature) return fail('INVALID_REQUEST', '缺少设备验证参数');
  const license = await loadLicense(env, key); if (!license) return fail('LICENSE_NOT_FOUND', '授权码不存在', 404);
  const device = await env.DB.prepare('SELECT public_key FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL').bind(license.id, deviceId).first<{ public_key: string | null }>();
  const row = await env.DB.prepare('SELECT id,expires_at FROM device_challenges WHERE license_id=? AND device_id=? AND nonce=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1').bind(license.id, deviceId, nonce).first<{ id: string; expires_at: string }>();
  if (!device?.public_key || !row || new Date(row.expires_at).getTime() <= Date.now()) return fail('INVALID_DEVICE_SIGNATURE', '设备验证失败', 403);
  try {
    const raw = device.public_key.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
    const publicKey = await crypto.subtle.importKey('spki', Uint8Array.from(atob(raw), c => c.charCodeAt(0)), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, unb64url(signature), encoder.encode(nonce));
    if (!ok) return fail('INVALID_DEVICE_SIGNATURE', '设备签名验证失败', 403);
    const used = await env.DB.prepare('UPDATE device_challenges SET used_at=? WHERE id=? AND used_at IS NULL').bind(nowIso(), row.id).run();
    if (!used.meta.changes) return fail('CHALLENGE_ALREADY_USED', '设备挑战已被使用', 409);
    await audit(env, req, 'DEVICE_VERIFIED', null, license.id, deviceId);
    return json({ success: true, verified: true, deviceProof: await issueDeviceProof(env, license.id, deviceId), proofExpiresInSeconds: 600 });
  } catch { return fail('INVALID_DEVICE_SIGNATURE', '设备签名格式错误', 403); }
}
async function login(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown'; if (!await rateLimit(env, `login:${ip}`, 5, 60)) return fail('RATE_LIMITED', '登录尝试过多，请稍后再试', 429);
  const body = await readJson(req); const passwordOk = !!env.ADMIN_PASSWORD && safeEqual(String(body.password || ''), env.ADMIN_PASSWORD); const turnstileOk = await verifyTurnstile(req, env, String(body.turnstileToken || ''));
  if (!passwordOk || !turnstileOk) { await audit(env, req, 'ADMIN_LOGIN_FAILED'); return fail('LOGIN_FAILED', '密码或验证码错误', 403); }
  await audit(env, req, 'ADMIN_LOGIN_SUCCESS');
  return json({ success: true }, 200, { 'set-cookie': `cleanc_session=${await createSession(env)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800` });
}
async function testCanonicalDomain(origin: string): Promise<boolean> {
  try {
    const r = await fetch(`${origin}/api/v1/health`, { headers: { 'user-agent': 'CleanC-License-Domain-Check/2.0' }, redirect: 'error' });
    if (!r.ok) return false; const d = await r.json() as { status?: string; service?: string }; return d.status === 'ok' && d.service === 'cleanc-license-server';
  } catch { return false; }
}
async function adminApi(req: Request, env: Env, path: string): Promise<Response> {
  const write = ['POST','PUT','PATCH','DELETE'].includes(req.method);
  if (!await requireAdmin(req, env, write)) return fail(write ? 'CSRF_OR_AUTH_FAILED' : 'UNAUTHORIZED', '未授权', write ? 403 : 401);
  if (path === '/admin/api/session' && req.method === 'GET') return json({ success: true, csrfToken: await csrfToken(req, env) });
  if (path === '/admin/api/logout' && req.method === 'POST') return json({ success: true }, 200, { 'set-cookie': 'cleanc_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
  if (path === '/admin/api/dashboard' && req.method === 'GET') {
    const l = await env.DB.prepare(`SELECT COUNT(*) total,SUM(CASE WHEN (${effectiveStatusSql('licenses')})='active' THEN 1 ELSE 0 END) active,SUM(CASE WHEN status='disabled' THEN 1 ELSE 0 END) disabled FROM licenses WHERE deleted_at IS NULL`).first<any>();
    const d = await env.DB.prepare('SELECT COUNT(*) c FROM devices WHERE revoked_at IS NULL').first<{ c:number }>();
    return json({ success:true, stats:{ total:l?.total||0, active:l?.active||0, disabled:l?.disabled||0, devices:d?.c||0 } });
  }
  if (path === '/admin/api/licenses' && req.method === 'GET') {
    const { results } = await env.DB.prepare('SELECT l.*,(SELECT COUNT(*) FROM devices d WHERE d.license_id=l.id AND d.revoked_at IS NULL) device_count FROM licenses l WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 500').all();
    return json({ success:true, licenses:results });
  }
  if (path === '/admin/api/licenses' && req.method === 'POST') {
    const body = await readJson(req); const count = positiveInt(body.count, 1, 15); const maxDevices = positiveInt(body.maxDevices, 1, 1000);
    if (!count || !maxDevices) return fail('INVALID_NUMBER', '数量必须 1-15，设备上限必须 1-1000');
    const type = ['permanent','duration','fixed'].includes(String(body.licenseType)) ? String(body.licenseType) : 'permanent';
    const durationDays = type === 'duration' ? positiveInt(body.durationDays, 365, 36500) : null; if (type === 'duration' && !durationDays) return fail('INVALID_DURATION', '有效天数必须为 1-36500 的整数');
    const expiresAt = type === 'fixed' ? validDate(body.expiresAt) : null; if (type === 'fixed' && (!expiresAt || new Date(expiresAt).getTime() <= Date.now())) return fail('INVALID_EXPIRES_AT', '固定到期时间必须是未来时间');
    const customKey = String(body.licenseKey || '').trim(); if (count > 1 && customKey) return fail('CUSTOM_KEY_BATCH_NOT_ALLOWED', '批量生成时不能指定单个自定义授权码'); if (customKey && !validCustomLicenseKey(customKey)) return fail('INVALID_LICENSE_KEY', '自定义授权码仅允许 6-80 位字母、数字、下划线和短横线');
    if (customKey && await env.DB.prepare('SELECT id FROM licenses WHERE license_key=?').bind(customKey).first()) return fail('LICENSE_KEY_EXISTS', '授权码已存在', 409);
    const created:string[]=[]; const statements:D1PreparedStatement[]=[]; const time=nowIso();
    for (let i=0;i<count;i++) { const id=uuid(); const k=customKey||randomLicenseKey(); created.push(k); statements.push(env.DB.prepare('INSERT INTO licenses(id,license_key,edition,status,license_type,duration_days,expires_at,max_devices,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(id,k,String(body.edition||'pro'),'active',type,durationDays,expiresAt,maxDevices,body.note?String(body.note).slice(0,500):null,time,time)); statements.push(env.DB.prepare('INSERT INTO audit_logs(id,event_type,ip,license_id,device_id,detail,created_at) VALUES(?,?,?,?,?,?,?)').bind(uuid(),count>1?'LICENSE_BATCH_CREATED':'LICENSE_CREATED',req.headers.get('cf-connecting-ip'),id,null,JSON.stringify({licenseKey:k}),time)); }
    try { await env.DB.batch(statements); } catch (e) { console.error(e); return fail('LICENSE_CREATE_FAILED', '授权码创建失败，请重试', 409); }
    return json({ success:true, licenseKeys:created });
  }
  const la=path.match(/^\/admin\/api\/licenses\/([^/]+)\/(disable|enable)$/); if (la && req.method==='POST') { const status=la[2]==='disable'?'disabled':'active'; const r=await env.DB.prepare('UPDATE licenses SET status=?,updated_at=? WHERE id=? AND deleted_at IS NULL').bind(status,nowIso(),la[1]).run(); if(!r.meta.changes)return fail('LICENSE_NOT_FOUND','授权不存在',404); await audit(env,req,status==='disabled'?'LICENSE_DISABLED':'LICENSE_ENABLED',null,la[1]); return json({success:true}); }
  if (path==='/admin/api/devices'&&req.method==='GET') { const {results}=await env.DB.prepare('SELECT d.*,l.license_key FROM devices d JOIN licenses l ON l.id=d.license_id ORDER BY d.last_seen_at DESC LIMIT 500').all(); return json({success:true,devices:results}); }
  const dr=path.match(/^\/admin\/api\/devices\/([^/]+)\/revoke$/); if(dr&&req.method==='POST'){const r=await env.DB.prepare('UPDATE devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL').bind(nowIso(),dr[1]).run();if(!r.meta.changes)return fail('DEVICE_NOT_FOUND','设备不存在或已解绑',404);await audit(env,req,'DEVICE_REVOKED',{id:dr[1]});return json({success:true});}
  if(path==='/admin/api/logs'&&req.method==='GET'){const {results}=await env.DB.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500').all();return json({success:true,logs:results});}
  if(path==='/admin/api/settings'&&req.method==='GET')return json({success:true,currentOrigin:new URL(req.url).origin,bootstrapBaseUrl:configuredBootstrapUrl(req,env),canonicalBaseUrl:await canonicalBaseUrl(req,env),turnstileSiteKey:env.TURNSTILE_SITE_KEY||''});
  if(path==='/admin/api/settings/domain'&&req.method==='POST'){const body=await readJson(req);if(!env.ADMIN_PASSWORD||!safeEqual(String(body.password||''),env.ADMIN_PASSWORD)||!await verifyTurnstile(req,env,String(body.turnstileToken||'')))return fail('REAUTH_FAILED','二次验证失败',403);const next=normalizeHttpsOrigin(String(body.baseUrl||''));if(!next)return fail('INVALID_DOMAIN','域名格式不正确，只允许公网 HTTPS 域名');if(!await testCanonicalDomain(next))return fail('DOMAIN_NOT_READY','域名尚未正确绑定到此 CleanC Worker',400);const old=await getSetting(env,'PRIMARY_BASE_URL');await env.DB.batch([env.DB.prepare("INSERT INTO system_settings(setting_key,setting_value,updated_at) VALUES('PRIMARY_BASE_URL',?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at").bind(next,nowIso()),env.DB.prepare('INSERT INTO domain_history(id,old_url,new_url,ip,created_at) VALUES(?,?,?,?,?)').bind(uuid(),old,next,req.headers.get('cf-connecting-ip'),nowIso())]);await audit(env,req,'DOMAIN_CHANGED',{old,next});return json({success:true,canonicalBaseUrl:next});}
  if(path==='/admin/api/settings/domain/rollback'&&req.method==='POST'){const body=await readJson(req);if(!env.ADMIN_PASSWORD||!safeEqual(String(body.password||''),env.ADMIN_PASSWORD)||!await verifyTurnstile(req,env,String(body.turnstileToken||'')))return fail('REAUTH_FAILED','二次验证失败',403);const old=await getSetting(env,'PRIMARY_BASE_URL'),fallback=configuredBootstrapUrl(req,env);await env.DB.prepare("DELETE FROM system_settings WHERE setting_key='PRIMARY_BASE_URL'").run();await audit(env,req,'DOMAIN_ROLLBACK',{old,next:fallback});return json({success:true,canonicalBaseUrl:fallback});}
  return fail('NOT_FOUND','接口不存在',404);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const path = new URL(req.url).pathname;
    try {
      if (path==='/api/v1/health'&&req.method==='GET') return json({status:'ok',service:'cleanc-license-server',apiVersion:2});
      if (path==='/api/v1/meta'&&req.method==='GET') return json({appName:env.APP_NAME||'CleanC',apiVersion:2,canonicalBaseUrl:await canonicalBaseUrl(req,env)});
      if (path==='/bootstrap/v1/config'&&req.method==='GET') { const payload:JsonObject={apiVersion:2,canonicalBaseUrl:await canonicalBaseUrl(req,env),issuedAt:nowIso()}; return json({...payload,...await signObject(env,payload)}); }
      if (path==='/api/v1/license/activate'&&req.method==='POST') return activate(req,env);
      if (path==='/api/v1/license/validate'&&req.method==='POST') return validateOrRefresh(req,env,'validate');
      if (path==='/api/v1/license/refresh'&&req.method==='POST') return validateOrRefresh(req,env,'refresh');
      if (path==='/api/v1/device/challenge'&&req.method==='POST') return challenge(req,env);
      if (path==='/api/v1/device/verify'&&req.method==='POST') return verifyDevice(req,env);
      if (path==='/admin/api/login'&&req.method==='POST') return login(req,env);
      if (path.startsWith('/admin/api/')) return adminApi(req,env,path);
      if (path==='/admin'||path==='/admin/'||path==='/admin/login') return html(adminPage(env.TURNSTILE_SITE_KEY||''));
      if (path==='/') return Response.redirect(new URL('/admin',req.url).toString(),302);
      return fail('NOT_FOUND','资源不存在',404);
    } catch(error) {
      console.error(error);
      if(error instanceof Error&&error.message==='INVALID_CONTENT_TYPE')return fail('INVALID_CONTENT_TYPE','请求必须使用 application/json',415);
      return fail('SERVER_ERROR','服务器内部错误',500);
    }
  }
};

