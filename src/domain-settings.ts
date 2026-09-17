import type { Env } from './worker';
import { validPasswordAdminSession } from './admin-password';

const encoder = new TextEncoder();

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
    },
  });
}

function b64url(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function hmac(secret: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return b64url(await crypto.subtle.sign('HMAC', key, encoder.encode(text)));
}

function getCookie(request: Request, name: string): string {
  return (request.headers.get('cookie') || '')
    .split(/;\s*/)
    .find(value => value.startsWith(name + '='))
    ?.slice(name.length + 1) || '';
}

function safeEqual(a: string, b: string): boolean {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function validAdminWrite(request: Request, env: Env): Promise<boolean> {
  if (!await validPasswordAdminSession(request, env)) return false;
  const cookie = getCookie(request, 'cleanc_session');
  const expected = await hmac(env.SESSION_SECRET, `csrf:${cookie}`);
  return safeEqual(request.headers.get('x-csrf-token') || '', expected);
}

function normalizeHttpsOrigin(input: string): string | null {
  try {
    const url = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
    const host = url.hostname.toLowerCase();
    const privateHost = host === 'localhost' || host === '::1' || /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host);
    if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash || privateHost) return null;
    return `https://${host}${url.port ? `:${url.port}` : ''}`;
  } catch {
    return null;
  }
}

async function getSetting(env: Env, key: string): Promise<string | null> {
  return (await env.DB.prepare(
    'SELECT setting_value FROM system_settings WHERE setting_key=?',
  ).bind(key).first<{ setting_value: string }>())?.setting_value || null;
}

function configuredBootstrapUrl(request: Request, env: Env): string {
  const configured = String(env.BOOTSTRAP_BASE_URL || '').trim().replace(/\/$/, '');
  return configured || new URL(request.url).origin;
}

async function audit(env: Env, request: Request, eventType: string, detail: unknown = null): Promise<void> {
  await env.DB.prepare(`
    INSERT INTO audit_logs(id,event_type,ip,license_id,device_id,detail,created_at)
    VALUES(?,?,?,?,?,?,?)
  `).bind(
    crypto.randomUUID(),
    eventType,
    request.headers.get('cf-connecting-ip'),
    null,
    null,
    detail == null ? null : JSON.stringify(detail),
    new Date().toISOString(),
  ).run();
}

export async function handleDomainSettings(request: Request, env: Env): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  if (request.method !== 'POST') return null;
  if (path !== '/admin/api/settings/domain' && path !== '/admin/api/settings/domain/rollback') return null;

  if (!await validAdminWrite(request, env)) {
    return json({ success: false, code: 'CSRF_OR_AUTH_FAILED', message: '未授权' }, 403);
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return json({ success: false, code: 'INVALID_JSON', message: '请求格式错误' }, 400);
  }

  if (!env.ADMIN_PASSWORD || !safeEqual(String(body.password || ''), env.ADMIN_PASSWORD)) {
    return json({ success: false, code: 'REAUTH_FAILED', message: '管理员密码二次验证失败' }, 403);
  }

  if (path === '/admin/api/settings/domain') {
    const next = normalizeHttpsOrigin(String(body.baseUrl || ''));
    if (!next) {
      return json({ success: false, code: 'INVALID_DOMAIN', message: '域名格式不正确，只允许公网 HTTPS 域名' }, 400);
    }

    // 不再从 Pages Function 内部 fetch 自己的自定义域名。
    // 当前请求本身已经成功通过该域名进入当前 CleanC 后台，
    // 因此“目标域名 == 当前访问 Origin”就是最直接、最可靠的绑定证明。
    const currentOrigin = new URL(request.url).origin.toLowerCase();
    if (next.toLowerCase() !== currentOrigin) {
      return json({
        success: false,
        code: 'OPEN_TARGET_DOMAIN_FIRST',
        message: `请先使用目标域名打开后台：${next}/admin，然后再在该页面保存这个域名。`,
      }, 400);
    }

    const old = await getSetting(env, 'PRIMARY_BASE_URL');
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO system_settings(setting_key,setting_value,updated_at)
        VALUES('PRIMARY_BASE_URL',?,?)
        ON CONFLICT(setting_key) DO UPDATE SET
          setting_value=excluded.setting_value,
          updated_at=excluded.updated_at
      `).bind(next, now),
      env.DB.prepare(`
        INSERT INTO domain_history(id,old_url,new_url,ip,created_at)
        VALUES(?,?,?,?,?)
      `).bind(crypto.randomUUID(), old, next, request.headers.get('cf-connecting-ip'), now),
    ]);
    await audit(env, request, 'DOMAIN_CHANGED', { old, next, verifiedBy: 'current-origin' });
    return json({ success: true, canonicalBaseUrl: next });
  }

  const old = await getSetting(env, 'PRIMARY_BASE_URL');
  const fallback = configuredBootstrapUrl(request, env);
  await env.DB.prepare("DELETE FROM system_settings WHERE setting_key='PRIMARY_BASE_URL'").run();
  await audit(env, request, 'DOMAIN_ROLLBACK', { old, next: fallback });
  return json({ success: true, canonicalBaseUrl: fallback });
}
