import type { ConfigCheck, Env, JsonObject } from './types';

export const encoder = new TextEncoder();
export const decoder = new TextDecoder();
export const nowIso = () => new Date().toISOString();
export const uuid = () => crypto.randomUUID();
export const SESSION_COOKIE = '__Host-cleanc_session';
const MAX_JSON_BYTES = 32 * 1024;

export function b64url(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function decodeB64url(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function pemToArrayBuffer(pem: string, begin: string, end: string): ArrayBuffer {
  const raw = pem.replace(begin, '').replace(end, '').replace(/\s+/g, '');
  if (!raw) throw new Error('PEM_EMPTY');
  const binary = atob(raw);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToPem(buffer: ArrayBuffer, label: string): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = btoa(binary);
  const lines = base64.match(/.{1,64}/g)?.join('\n') || base64;
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

export function safeEqual(a: string, b: string): boolean {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

export function baseHeaders(): HeadersInit {
  return {
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
  };
}

export function json(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...baseHeaders(), ...headers },
  });
}

export function fail(code: string, message: string, status = 400): Response {
  return json({ success: false, code, message }, status);
}

export function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      ...baseHeaders(),
      'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://challenges.cloudflare.com; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    },
  });
}

export async function readJson(req: Request): Promise<Record<string, unknown>> {
  const type = (req.headers.get('content-type') || '').toLowerCase();
  if (!type.includes('application/json')) throw new Error('INVALID_CONTENT_TYPE');
  const declaredLength = Number(req.headers.get('content-length') || 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_JSON_BYTES) throw new Error('PAYLOAD_TOO_LARGE');
  const raw = await req.arrayBuffer();
  if (raw.byteLength > MAX_JSON_BYTES) throw new Error('PAYLOAD_TOO_LARGE');
  try {
    const parsed = JSON.parse(decoder.decode(raw));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('INVALID_JSON');
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof Error && error.message === 'INVALID_JSON') throw error;
    throw new Error('INVALID_JSON');
  }
}

export function boundedText(value: unknown, max: number, trim = true): string {
  const raw = String(value ?? '');
  const text = trim ? raw.trim() : raw;
  return text.length <= max ? text : '';
}

export function optionalText(value: unknown, max: number): string | null {
  const text = String(value ?? '').trim();
  if (!text) return null;
  return text.slice(0, max);
}

export async function hmac(secret: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, encoder.encode(text)));
}

export async function createSession(env: Env): Promise<string> {
  const payload = b64url(encoder.encode(JSON.stringify({ exp: Date.now() + 8 * 3600_000, nonce: uuid() })));
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}

export function getCookie(req: Request, name: string): string {
  return (req.headers.get('cookie') || '')
    .split(/;\s*/)
    .find(value => value.startsWith(`${name}=`))
    ?.slice(name.length + 1) || '';
}

export async function validSession(req: Request, env: Env): Promise<boolean> {
  const [payload, signature] = getCookie(req, SESSION_COOKIE).split('.');
  if (!payload || !signature || !safeEqual(signature, await hmac(env.SESSION_SECRET, payload))) return false;
  try {
    const parsed = JSON.parse(decoder.decode(decodeB64url(payload))) as { exp?: number };
    return typeof parsed.exp === 'number' && parsed.exp > Date.now();
  } catch {
    return false;
  }
}

export async function csrfToken(req: Request, env: Env): Promise<string> {
  return hmac(env.SESSION_SECRET, `csrf:${getCookie(req, SESSION_COOKIE)}`);
}

export async function requireAdmin(req: Request, env: Env, write = false): Promise<boolean> {
  if (!await validSession(req, env)) return false;
  if (!write) return true;
  return safeEqual(req.headers.get('x-csrf-token') || '', await csrfToken(req, env));
}

export async function audit(env: Env, req: Request, eventType: string, detail: unknown = null, licenseId: string | null = null, deviceId: string | null = null): Promise<void> {
  await env.DB.prepare('INSERT INTO audit_logs(id,event_type,ip,license_id,device_id,detail,created_at) VALUES(?,?,?,?,?,?,?)')
    .bind(uuid(), eventType, req.headers.get('cf-connecting-ip'), licenseId, deviceId, detail == null ? null : JSON.stringify(detail), nowIso())
    .run();
}

export async function rateLimit(env: Env, key: string, max: number, seconds: number): Promise<boolean> {
  const current = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(`INSERT INTO rate_limits(bucket_key,count,window_start) VALUES(?,1,?)
    ON CONFLICT(bucket_key) DO UPDATE SET
      count=CASE WHEN ?-window_start>=? THEN 1 ELSE count+1 END,
      window_start=CASE WHEN ?-window_start>=? THEN ? ELSE window_start END
    RETURNING count`)
    .bind(key, current, current, seconds, current, seconds, current)
    .first<{ count: number }>();
  return !!row && row.count <= max;
}

export async function verifyTurnstile(req: Request, env: Env, token: string): Promise<boolean> {
  if (!env.TURNSTILE_SECRET || !token || token.length > 4096) return false;
  const form = new FormData();
  form.set('secret', env.TURNSTILE_SECRET);
  form.set('response', token);
  const ip = req.headers.get('cf-connecting-ip');
  if (ip) form.set('remoteip', ip);
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
    if (!response.ok) return false;
    const result = await response.json() as { success?: boolean; hostname?: string };
    return result.success === true && String(result.hostname || '').toLowerCase() === new URL(req.url).hostname.toLowerCase();
  } catch {
    return false;
  }
}

export async function getSetting(env: Env, key: string): Promise<string | null> {
  return (await env.DB.prepare('SELECT setting_value FROM system_settings WHERE setting_key=?')
    .bind(key).first<{ setting_value: string }>())?.setting_value || null;
}

export function normalizeHttpsOrigin(input: string): string | null {
  try {
    const url = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
    const host = url.hostname.toLowerCase();
    const isIpv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
    const isIpv6 = host.includes(':');
    const reservedSuffix = /\.(?:local|localhost|internal|invalid|test)$/i.test(host);
    if (
      url.protocol !== 'https:' || url.username || url.password || url.port ||
      url.pathname !== '/' || url.search || url.hash || !host.includes('.') ||
      host.length > 253 || isIpv4 || isIpv6 || reservedSuffix
    ) return null;
    return `https://${host}`;
  } catch {
    return null;
  }
}

export function configuredBootstrapUrl(req: Request, env: Env): string {
  const configured = normalizeHttpsOrigin(String(env.BOOTSTRAP_BASE_URL || '').trim());
  return configured || new URL(req.url).origin;
}

export async function canonicalBaseUrl(req: Request, env: Env): Promise<string> {
  return (await getSetting(env, 'PRIMARY_BASE_URL')) || configuredBootstrapUrl(req, env);
}

export async function importPrivateKey(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(pem, '-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----'),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
}

export async function normalizePublicKeyPem(pem: string): Promise<string | null> {
  try {
    if (!pem || pem.length > 4000) return null;
    const key = await crypto.subtle.importKey(
      'spki',
      pemToArrayBuffer(pem, '-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----'),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );
    return arrayBufferToPem(await crypto.subtle.exportKey('spki', key), 'PUBLIC KEY');
  } catch {
    return null;
  }
}

export async function verifyP256Signature(publicKeyPem: string, signatureB64Url: string, message: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'spki',
      pemToArrayBuffer(publicKeyPem, '-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----'),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      decodeB64url(signatureB64Url),
      encoder.encode(message),
    );
  } catch {
    return false;
  }
}

export async function signObject(env: Env, object: JsonObject): Promise<{ signedPayload: string; signature: string; signatureAlgorithm: string; signatureFormat: string }> {
  const serialized = JSON.stringify(object);
  const key = await importPrivateKey(env.LICENSE_SIGNING_PRIVATE_KEY);
  const signature = b64url(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, encoder.encode(serialized)));
  return {
    signedPayload: b64url(encoder.encode(serialized)),
    signature,
    signatureAlgorithm: 'ECDSA_P256_SHA256',
    signatureFormat: 'IEEE_P1363',
  };
}

export function randomLicenseKey(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const limit = 256 - (256 % chars.length);
  let out = '';
  while (out.length < 16) {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      if (byte >= limit) continue;
      out += chars[byte % chars.length];
      if (out.length === 16) break;
    }
  }
  return `CLC-${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8, 12)}-${out.slice(12, 16)}`;
}

export function validCustomLicenseKey(value: string): boolean {
  return /^[A-Za-z0-9_-]{6,80}$/.test(value);
}

export function positiveInt(value: unknown, fallback: number, max: number): number | null {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) && number >= 1 && number <= max ? number : null;
}

export function validDate(value: unknown): string | null {
  if (!value) return null;
  const date = new Date(String(value));
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

let configCheckPromise: Promise<ConfigCheck> | null = null;

export async function checkRuntimeConfig(env: Env): Promise<ConfigCheck> {
  if (configCheckPromise) return configCheckPromise;
  configCheckPromise = (async () => {
    const missing: string[] = [];
    const invalid: string[] = [];
    const requireValue = (name: keyof Env) => {
      if (!String(env[name] || '').trim()) missing.push(String(name));
    };
    requireValue('ADMIN_PASSWORD');
    requireValue('SESSION_SECRET');
    requireValue('DEVICE_PROOF_SECRET');
    requireValue('TURNSTILE_SECRET');
    requireValue('LICENSE_SIGNING_PRIVATE_KEY');
    requireValue('TURNSTILE_SITE_KEY');
    requireValue('BOOTSTRAP_BASE_URL');

    if (env.ADMIN_PASSWORD && env.ADMIN_PASSWORD.length < 8) invalid.push('ADMIN_PASSWORD');
    if (env.SESSION_SECRET && env.SESSION_SECRET.length < 32) invalid.push('SESSION_SECRET');
    if (env.DEVICE_PROOF_SECRET && env.DEVICE_PROOF_SECRET.length < 32) invalid.push('DEVICE_PROOF_SECRET');
    if (env.SESSION_SECRET && env.DEVICE_PROOF_SECRET && safeEqual(env.SESSION_SECRET, env.DEVICE_PROOF_SECRET)) invalid.push('SESSION_SECRET/DEVICE_PROOF_SECRET');
    if (env.BOOTSTRAP_BASE_URL && !normalizeHttpsOrigin(env.BOOTSTRAP_BASE_URL)) invalid.push('BOOTSTRAP_BASE_URL');
    const leaseHours = Number(env.LEASE_HOURS || 72);
    if (!Number.isFinite(leaseHours) || leaseHours < 1 || leaseHours > 720) invalid.push('LEASE_HOURS');
    if (env.LICENSE_SIGNING_PRIVATE_KEY) {
      try { await importPrivateKey(env.LICENSE_SIGNING_PRIVATE_KEY); }
      catch { invalid.push('LICENSE_SIGNING_PRIVATE_KEY'); }
    }
    return { ok: missing.length === 0 && invalid.length === 0, missing, invalid };
  })();
  return configCheckPromise;
}
