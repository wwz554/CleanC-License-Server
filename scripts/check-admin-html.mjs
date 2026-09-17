import { adminPage } from '../src/admin.ts';
import { prepareAuthenticatedAdminResponse } from '../src/authenticated-admin.ts';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function checkInlineScripts(html, label) {
  const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
    .map(match => match[1])
    .filter(script => script.trim());
  assert(scripts.length > 0, `${label}: 没有找到内联脚本`);
  for (const script of scripts) {
    // 这一步检查浏览器实际接收到的 JavaScript 是否能被解析。
    new Function(script);
  }
}

const raw = adminPage('password-only-disabled');
checkInlineScripts(raw, '原始后台页面');

const request = new Request('https://cleanc-license-server.pages.dev/admin', {
  headers: {
    cookie: 'cleanc_session=test-payload.test-signature',
  },
});
const env = {
  SESSION_SECRET: 'ci-session-secret',
};
const response = new Response(raw, {
  status: 200,
  headers: { 'content-type': 'text/html; charset=utf-8' },
});
const prepared = await prepareAuthenticatedAdminResponse(response, request, env);
const html = await prepared.text();

assert(
  html.includes('<div id="login" class="login glass hidden" style="display:none!important">'),
  '已登录后台仍然显示旧登录壳',
);
assert(
  html.includes('<div id="app" class="app" style="display:block">'),
  '已登录后台没有直接显示管理 App',
);
assert(!html.includes('licenseTypeChanged();boot();'), '已登录后台仍依赖 boot() 二次判断 Session');
assert(html.includes('licenseTypeChanged();loadDashboard();'), '已登录后台没有直接加载仪表盘');
assert(/var csrf='[^']+';/.test(html), '已登录后台没有注入 CSRF Token');
assert(!html.includes('challenges.cloudflare.com/turnstile/v0/api.js'), '已登录后台仍加载 Turnstile');

checkInlineScripts(html, '已登录后台页面');
console.log('Admin HTML/JS check passed');
