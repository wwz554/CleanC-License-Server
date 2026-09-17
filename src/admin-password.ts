import type { Env } from './worker';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function json(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  return Response.json(data, {
    status,
    headers: {
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      ...headers,
    },
  });
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    },
  });
}

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
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
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

async function createSession(env: Env): Promise<string> {
  const payload = b64url(encoder.encode(JSON.stringify({
    exp: Date.now() + 8 * 3600_000,
    nonce: crypto.randomUUID(),
  })));
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}

export async function validPasswordAdminSession(request: Request, env: Env): Promise<boolean> {
  const [payload, signature] = getCookie(request, 'cleanc_session').split('.');
  if (!payload || !signature) return false;
  if (!safeEqual(signature, await hmac(env.SESSION_SECRET, payload))) return false;
  try {
    const parsed = JSON.parse(decoder.decode(unb64url(payload))) as { exp?: number };
    return typeof parsed.exp === 'number' && parsed.exp > Date.now();
  } catch {
    return false;
  }
}

async function csrfToken(request: Request, env: Env): Promise<string> {
  return hmac(env.SESSION_SECRET, `csrf:${getCookie(request, 'cleanc_session')}`);
}

async function validAdminWrite(request: Request, env: Env): Promise<boolean> {
  if (!await validPasswordAdminSession(request, env)) return false;
  return safeEqual(
    request.headers.get('x-csrf-token') || '',
    await csrfToken(request, env),
  );
}

async function consumeRateLimit(env: Env, key: string, max: number, seconds: number): Promise<boolean> {
  const current = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(`
    INSERT INTO rate_limits(bucket_key,count,window_start) VALUES(?,1,?)
    ON CONFLICT(bucket_key) DO UPDATE SET
      count=CASE WHEN ?-window_start>=? THEN 1 ELSE count+1 END,
      window_start=CASE WHEN ?-window_start>=? THEN ? ELSE window_start END
    RETURNING count
  `).bind(key, current, current, seconds, current, seconds, current)
    .first<{ count: number }>();
  return !!row && row.count <= max;
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

async function testCanonicalDomain(origin: string): Promise<boolean> {
  try {
    const response = await fetch(`${origin}/api/v1/health`, {
      headers: { 'user-agent': 'CleanC-License-Domain-Check/3.0' },
      redirect: 'error',
    });
    if (!response.ok) return false;
    const data = await response.json() as { status?: string; service?: string };
    return data.status === 'ok' && data.service === 'cleanc-license-server';
  } catch {
    return false;
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

function loginPage(): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CleanC License</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17233b;background:radial-gradient(circle at 5% 8%,#d9efff,transparent 34%),radial-gradient(circle at 92% 4%,#eadfff,transparent 38%),linear-gradient(135deg,#f8fbff,#eef4ff);min-height:100vh}.glass{background:rgba(255,255,255,.67);backdrop-filter:blur(28px) saturate(150%);border:1px solid rgba(255,255,255,.88);box-shadow:0 24px 70px rgba(43,72,140,.14),inset 0 1px 0 #fff;border-radius:28px}.login{width:min(430px,calc(100% - 32px));padding:34px;position:absolute;left:50%;top:50%;transform:translate(-50%,-50%)}.logo{width:56px;height:56px;border-radius:18px;display:grid;place-items:center;font-size:26px;font-weight:800;color:#fff;background:linear-gradient(145deg,#4a8cff,#765cff)}h1{margin:26px 0 10px}.muted{color:#72809a}.notice{padding:11px 13px;border-radius:12px;background:#eef4ff;color:#4c628f;margin:16px 0}.bad{color:#b83250}.ok{color:#26844a}input,button{font:inherit;width:100%;padding:13px 14px;border-radius:14px}input{border:1px solid #dce5f4;background:#ffffffdf}button{margin-top:14px;border:0;cursor:pointer;font-weight:700;background:linear-gradient(135deg,#4d88ff,#735cff);color:#fff}button:disabled{opacity:.58;cursor:not-allowed}#msg{min-height:22px;margin:12px 0 0}
</style>
</head>
<body>
<div class="login glass">
  <div class="logo">C</div>
  <h1>CleanC License</h1>
  <p class="muted">管理员控制台</p>
  <div class="notice">当前后台使用“管理员密码 + 登录限流”验证，不再使用 Cloudflare Turnstile。</div>
  <form id="loginForm" action="javascript:void(0)">
    <input id="password" type="password" autocomplete="current-password" placeholder="管理员密码" autofocus>
    <button id="loginBtn" type="submit">登录</button>
    <p id="msg" class="muted"></p>
  </form>
</div>
<script>
(function(){
  var form=document.getElementById('loginForm');
  var input=document.getElementById('password');
  var btn=document.getElementById('loginBtn');
  var msg=document.getElementById('msg');
  form.addEventListener('submit',async function(e){
    e.preventDefault();
    var password=input.value;
    if(!password){msg.className='bad';msg.textContent='请输入管理员密码';return;}
    btn.disabled=true;btn.textContent='登录中…';msg.className='muted';msg.textContent='正在验证…';
    try{
      var response=await fetch('/admin/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:password})});
      var data={};try{data=await response.json()}catch(_){}
      if(!response.ok||!data.success){msg.className='bad';msg.textContent=data.message||data.code||('登录失败（HTTP '+response.status+'）');return;}
      var check=await fetch('/admin/api/session',{cache:'no-store'});
      if(!check.ok){msg.className='bad';msg.textContent='密码验证成功，但浏览器没有保存后台 Session。请允许本站 Cookie 后重试。';return;}
      msg.className='ok';msg.textContent='登录成功，正在进入后台…';
      location.replace('/admin');
    }catch(err){
      msg.className='bad';msg.textContent='网络请求失败：'+(err&&err.message?err.message:'未知错误');
    }finally{
      btn.disabled=false;btn.textContent='登录';
    }
  });
})();
</script>
</body>
</html>`;
}

export async function handlePasswordAdmin(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if ((path === '/admin' || path === '/admin/' || path === '/admin/login') && request.method === 'GET') {
    if (!await validPasswordAdminSession(request, env)) return html(loginPage());
    return null;
  }

  if (path === '/admin/api/login' && request.method === 'POST') {
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (!await consumeRateLimit(env, `login:${ip}`, 5, 60)) {
      return json({ success: false, code: 'RATE_LIMITED', message: '登录尝试过多，请 1 分钟后再试' }, 429);
    }
    let body: Record<string, unknown>;
    try {
      body = await request.json() as Record<string, unknown>;
    } catch {
      return json({ success: false, code: 'INVALID_JSON', message: '请求格式错误' }, 400);
    }
    const password = String(body.password || '');
    if (!env.ADMIN_PASSWORD || !safeEqual(password, env.ADMIN_PASSWORD)) {
      await audit(env, request, 'ADMIN_LOGIN_FAILED');
      return json({ success: false, code: 'LOGIN_FAILED', message: '管理员密码错误' }, 403);
    }
    await audit(env, request, 'ADMIN_LOGIN_SUCCESS');
    const session = await createSession(env);
    return json({ success: true }, 200, {
      'set-cookie': `cleanc_session=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
    });
  }

  if (path === '/admin/api/settings/domain' && request.method === 'POST') {
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
    const next = normalizeHttpsOrigin(String(body.baseUrl || ''));
    if (!next) return json({ success: false, code: 'INVALID_DOMAIN', message: '域名格式不正确，只允许公网 HTTPS 域名' }, 400);
    if (!await testCanonicalDomain(next)) {
      return json({ success: false, code: 'DOMAIN_NOT_READY', message: '域名尚未正确绑定到当前 CleanC 授权服务' }, 400);
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
    await audit(env, request, 'DOMAIN_CHANGED', { old, next });
    return json({ success: true, canonicalBaseUrl: next });
  }

  if (path === '/admin/api/settings/domain/rollback' && request.method === 'POST') {
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
    const old = await getSetting(env, 'PRIMARY_BASE_URL');
    const fallback = configuredBootstrapUrl(request, env);
    await env.DB.prepare("DELETE FROM system_settings WHERE setting_key='PRIMARY_BASE_URL'").run();
    await audit(env, request, 'DOMAIN_ROLLBACK', { old, next: fallback });
    return json({ success: true, canonicalBaseUrl: fallback });
  }

  return null;
}

export async function stripTurnstileFromAdminResponse(response: Response): Promise<Response> {
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) return response;
  let body = await response.text();
  body = body.replace(/<script src="https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js"[^>]*><\/script>/g, '');
  body = body.replace(/<div id="loginTs"[^>]*><\/div>/g, '<div id="loginTs" class="hidden"></div>');
  body = body.replace(/<div id="settingsTs"[^>]*><\/div>/g, '<div id="settingsTs" class="hidden"></div>');
  body = body.replace(
    '先在 Cloudflare Pages 项目绑定 Custom Domain，并把该主机名加入 Turnstile Hostname Management，再在这里保存。系统会验证目标域名确实是当前 CleanC 授权服务。',
    '先在 Cloudflare Pages 项目绑定 Custom Domain，然后在这里保存。保存时只需要再次输入管理员密码，系统会验证目标域名确实是当前 CleanC 授权服务。',
  );
  const headers = new Headers(response.headers);
  headers.set('content-length', String(new TextEncoder().encode(body).byteLength));
  return new Response(body, { status: response.status, statusText: response.statusText, headers });
}
