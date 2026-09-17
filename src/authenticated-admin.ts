import type { Env } from './worker';

const encoder = new TextEncoder();

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

async function csrfToken(request: Request, env: Env): Promise<string> {
  return hmac(env.SESSION_SECRET, `csrf:${getCookie(request, 'cleanc_session')}`);
}

function jsString(value: string): string {
  return JSON.stringify(value).slice(1, -1);
}

/**
 * 原 worker 的管理页面历史上同时包含“登录壳”和“后台 App”。
 * 生产密码认证层已经在路由进入这里之前验证了 Session，因此这里直接
 * 输出已认证状态，避免浏览器再次依赖 boot() 判断登录状态而出现二次登录页。
 */
export async function prepareAuthenticatedAdminResponse(
  response: Response,
  request: Request,
  env: Env,
): Promise<Response> {
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) return response;

  const csrf = await csrfToken(request, env);
  let body = await response.text();

  // 后台已改为纯密码认证，移除 Turnstile 资源和占位组件。
  body = body.replace(
    /<script src="https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js"[^>]*><\/script>/g,
    '',
  );
  body = body.replace(/<div id="loginTs"[^>]*><\/div>/g, '<div id="loginTs" class="hidden"></div>');
  body = body.replace(/<div id="settingsTs"[^>]*><\/div>/g, '<div id="settingsTs" class="hidden"></div>');

  // Session 已由服务器验证：不要再显示旧登录壳，直接显示管理 App。
  body = body.replace(
    '<div id="login" class="login glass">',
    '<div id="login" class="login glass hidden" style="display:none!important">',
  );
  body = body.replace(
    '<div id="app" class="app">',
    '<div id="app" class="app" style="display:block">',
  );

  // 直接注入与当前 Session 对应的 CSRF，后台写操作无需再依赖 boot() 获取。
  body = body.replace("var csrf='';", `var csrf='${jsString(csrf)}';`);

  // 页面已经是已认证状态，直接加载仪表盘，不再让 boot() 二次判断 Session。
  body = body.replace('licenseTypeChanged();boot();', 'licenseTypeChanged();loadDashboard();');

  body = body.replace(
    '先在 Cloudflare Pages 项目绑定 Custom Domain，并把该主机名加入 Turnstile Hostname Management，再在这里保存。系统会验证目标域名确实是当前 CleanC 授权服务。',
    '先在 Cloudflare Pages 项目绑定 Custom Domain，然后在这里保存。保存时只需要再次输入管理员密码，系统会验证目标域名确实是当前 CleanC 授权服务。',
  );

  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.set('cache-control', 'no-store');
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
