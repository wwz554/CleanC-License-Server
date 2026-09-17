import { validPasswordAdminSession } from './admin-password';
import type { Env } from './worker';

const encoder = new TextEncoder();

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
      'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    },
  });
}

function escapeAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function b64url(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
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

async function createSession(env: Env): Promise<string> {
  const payload = b64url(encoder.encode(JSON.stringify({
    exp: Date.now() + 8 * 3600_000,
    nonce: crypto.randomUUID(),
  })));
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
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

type TurnstileResult = {
  success?: boolean;
  hostname?: string;
  action?: string;
  'error-codes'?: string[];
};

async function verifyTurnstile(request: Request, env: Env, token: string): Promise<TurnstileResult> {
  const secret = String(env.TURNSTILE_SECRET || '').trim();
  if (!secret) return { success: false, 'error-codes': ['missing-input-secret'] };
  if (!token || token.length > 2048) return { success: false, 'error-codes': ['missing-input-response'] };

  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        secret,
        response: token,
        remoteip: request.headers.get('cf-connecting-ip') || undefined,
        idempotency_key: crypto.randomUUID(),
      }),
    });
    if (!response.ok) return { success: false, 'error-codes': [`siteverify-http-${response.status}`] };
    return await response.json() as TurnstileResult;
  } catch {
    return { success: false, 'error-codes': ['internal-error'] };
  }
}

export function renderTurnstileLoginPage(siteKeyRaw: string): string {
  const siteKey = escapeAttr(siteKeyRaw.trim());
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CleanC License</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17233b;background:radial-gradient(circle at 5% 8%,#d9efff,transparent 34%),radial-gradient(circle at 92% 4%,#eadfff,transparent 38%),linear-gradient(135deg,#f8fbff,#eef4ff);min-height:100vh}.glass{background:rgba(255,255,255,.67);backdrop-filter:blur(28px) saturate(150%);border:1px solid rgba(255,255,255,.88);box-shadow:0 24px 70px rgba(43,72,140,.14),inset 0 1px 0 #fff;border-radius:28px}.login{width:min(430px,calc(100% - 32px));padding:34px;position:absolute;left:50%;top:50%;transform:translate(-50%,-50%)}.logo{width:56px;height:56px;border-radius:18px;display:grid;place-items:center;font-size:26px;font-weight:800;color:#fff;background:linear-gradient(145deg,#4a8cff,#765cff)}h1{margin:26px 0 10px}.muted{color:#72809a}.notice{padding:11px 13px;border-radius:12px;background:#eef4ff;color:#4c628f;margin:16px 0}.bad{color:#b83250}.ok{color:#26844a}.ts{min-height:65px;margin-top:14px}input,button{font:inherit;width:100%;padding:13px 14px;border-radius:14px}input{border:1px solid #dce5f4;background:#ffffffdf}button{margin-top:14px;border:0;cursor:pointer;font-weight:700;background:linear-gradient(135deg,#4d88ff,#735cff);color:#fff}button:disabled{opacity:.58;cursor:not-allowed}#msg{min-height:22px;margin:12px 0 0}
</style>
</head>
<body>
<div class="login glass">
  <div class="logo">C</div>
  <h1>CleanC License</h1>
  <p class="muted">管理员控制台</p>
  <div class="notice">管理员登录需要“密码 + Cloudflare Turnstile”，客户授权 API 不使用 Turnstile。</div>
  <form id="loginForm" action="javascript:void(0)">
    <input id="password" type="password" autocomplete="current-password" placeholder="管理员密码" autofocus>
    <div id="turnstileBox" class="cf-turnstile ts" data-sitekey="${siteKey}" data-action="admin-login"></div>
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
  function token(){var el=document.querySelector('input[name="cf-turnstile-response"]');return el&&el.value?el.value:''}
  function reset(){try{if(window.turnstile)window.turnstile.reset()}catch(_){}}
  form.addEventListener('submit',async function(e){
    e.preventDefault();
    var password=input.value;
    var turnstileToken=token();
    if(!password){msg.className='bad';msg.textContent='请输入管理员密码';return;}
    if(!turnstileToken){msg.className='bad';msg.textContent='请先完成人机验证';return;}
    btn.disabled=true;btn.textContent='登录中…';msg.className='muted';msg.textContent='正在验证…';
    try{
      var response=await fetch('/admin/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:password,turnstileToken:turnstileToken})});
      var data={};try{data=await response.json()}catch(_){}
      if(!response.ok||!data.success){msg.className='bad';msg.textContent=data.message||data.code||('登录失败（HTTP '+response.status+'）');reset();return;}
      var check=await fetch('/admin/api/session',{cache:'no-store'});
      if(!check.ok){msg.className='bad';msg.textContent='验证成功，但浏览器没有保存后台 Session。请允许本站 Cookie 后重试。';reset();return;}
      msg.className='ok';msg.textContent='登录成功，正在进入后台…';
      location.replace('/admin');
    }catch(err){
      msg.className='bad';msg.textContent='网络请求失败：'+(err&&err.message?err.message:'未知错误');reset();
    }finally{
      btn.disabled=false;btn.textContent='登录';
    }
  });
})();
</script>
</body>
</html>`;
}

export async function handleAdminTurnstile(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if ((path === '/admin' || path === '/admin/' || path === '/admin/login') && request.method === 'GET') {
    if (await validPasswordAdminSession(request, env)) return null;
    const siteKey = String(env.TURNSTILE_SITE_KEY || '').trim();
    if (!siteKey || !String(env.TURNSTILE_SECRET || '').trim()) {
      return html('<!doctype html><meta charset="utf-8"><title>CleanC</title><p style="font:16px sans-serif;padding:24px">后台 Turnstile 尚未配置，请在 Cloudflare Pages 中设置 TURNSTILE_SITE_KEY 和 TURNSTILE_SECRET。</p>', 503);
    }
    return html(renderTurnstileLoginPage(siteKey));
  }

  if (path !== '/admin/api/login' || request.method !== 'POST') return null;

  const siteKey = String(env.TURNSTILE_SITE_KEY || '').trim();
  const secret = String(env.TURNSTILE_SECRET || '').trim();
  if (!siteKey || !secret) {
    return json({ success: false, code: 'TURNSTILE_NOT_CONFIGURED', message: '后台 Turnstile 尚未配置' }, 503);
  }

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

  const token = String(body.turnstileToken || '');
  const verification = await verifyTurnstile(request, env, token);
  const expectedHost = url.hostname.toLowerCase();
  const verifiedHost = String(verification.hostname || '').toLowerCase();
  if (!verification.success || (verifiedHost && verifiedHost !== expectedHost)) {
    await audit(env, request, 'ADMIN_LOGIN_TURNSTILE_FAILED', {
      hostname: verification.hostname || null,
      errorCodes: verification['error-codes'] || [],
    });
    return json({ success: false, code: 'TURNSTILE_FAILED', message: '人机验证失败，请重新完成验证' }, 403);
  }

  const password = String(body.password || '');
  if (!env.ADMIN_PASSWORD || !safeEqual(password, env.ADMIN_PASSWORD)) {
    await audit(env, request, 'ADMIN_LOGIN_FAILED');
    return json({ success: false, code: 'LOGIN_FAILED', message: '管理员密码或人机验证错误' }, 403);
  }

  await audit(env, request, 'ADMIN_LOGIN_SUCCESS');
  const session = await createSession(env);
  return json({ success: true }, 200, {
    'set-cookie': `cleanc_session=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
  });
}
