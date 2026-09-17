import { prepareAuthenticatedAdminResponse } from '../src/authenticated-admin.ts';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function checkInlineScripts(html, label) {
  const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
    .map(match => match[1])
    .filter(script => script.trim());
  assert(scripts.length > 0, `${label}: 没有找到内联脚本`);
  for (const script of scripts) new Function(script);
}

const request = new Request('https://cleanc-license-server.pages.dev/admin', {
  headers: { cookie: 'cleanc_session=test-payload.test-signature' },
});
const env = { SESSION_SECRET: 'ci-session-secret' };
const response = new Response('<!doctype html><html><body>legacy shell</body></html>', {
  status: 200,
  headers: { 'content-type': 'text/html; charset=utf-8' },
});
const prepared = await prepareAuthenticatedAdminResponse(response, request, env);
const html = await prepared.text();

assert(html.includes('CleanC 授权服务管理中心'), '缺少后台主界面');
assert(html.includes('data-tab="dashboard"'), '缺少仪表盘菜单');
assert(html.includes('data-tab="licenses"'), '缺少授权管理菜单');
assert(html.includes('data-tab="devices"'), '缺少设备管理菜单');
assert(html.includes('data-tab="logs"'), '缺少操作日志菜单');
assert(html.includes('data-tab="settings"'), '缺少设置菜单');
assert(html.includes('var CSRF='), '没有注入 CSRF Token');
assert(!html.includes('challenges.cloudflare.com'), '已登录后台仍依赖 Turnstile');
assert(!html.includes('onclick='), '后台仍包含动态 inline onclick');
assert(!html.includes('boot();'), '后台仍依赖旧 boot() 登录判断');
assert(html.includes("addEventListener('click'"), '菜单/按钮没有使用事件监听器');

checkInlineScripts(html, '已登录后台页面');
console.log('Authenticated admin HTML/JS check passed');
