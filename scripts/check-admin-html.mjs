import { prepareAuthenticatedAdminResponse } from '../src/admin-dashboard.ts';
import { renderTurnstileLoginPage } from '../src/admin-turnstile.ts';

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

const loginHtml = renderTurnstileLoginPage('0x4AAAAAAA-ci-site-key');
assert(loginHtml.includes('https://challenges.cloudflare.com/turnstile/v0/api.js'), '登录页没有加载 Turnstile');
assert(loginHtml.includes('class="cf-turnstile'), '登录页缺少 Turnstile 组件');
assert(loginHtml.includes('data-action="admin-login"'), '登录页缺少 admin-login action');
assert(loginHtml.includes('turnstileToken:turnstileToken'), '登录请求没有发送 Turnstile token');
assert(loginHtml.includes("fetch('/admin/api/login'"), '登录页没有调用管理员登录接口');
assert(!loginHtml.includes('onclick='), 'Turnstile 登录页仍包含 inline onclick');
checkInlineScripts(loginHtml, 'Turnstile 登录页');

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
assert(!html.includes('challenges.cloudflare.com'), '已登录后台不应加载 Turnstile');
assert(!html.includes('onclick='), '后台仍包含 inline onclick');
assert(!html.includes('boot();'), '后台仍依赖旧 boot() 登录判断');
assert(html.includes("addEventListener('click'"), '菜单/按钮没有使用事件监听器');
assert(html.includes('data-action="delete-license"'), '缺少禁用授权删除操作');
assert(html.includes('data-action="delete-device"'), '缺少已解绑设备删除操作');
assert(html.includes('more-wrap'), '缺少授权三点下拉菜单');
assert(html.includes('id="licenseSearch"'), '缺少授权搜索框');
assert(html.includes('id="licenseStatusFilter"'), '缺少授权状态筛选');
assert(html.includes('id="licensePrevBtn"') && html.includes('id="licenseNextBtn"'), '缺少授权分页按钮');
assert(html.includes('id="deviceSearch"'), '缺少设备搜索框');
assert(html.includes('id="deviceBindingFilter"'), '缺少设备绑定状态筛选');
assert(html.includes('id="devicePrevBtn"') && html.includes('id="deviceNextBtn"'), '缺少设备分页按钮');
assert(html.includes('formatCustomLicenseKey'), '缺少自定义授权码自动格式化');

checkInlineScripts(html, '已登录后台页面');
console.log('Admin Turnstile login + authenticated dashboard HTML/JS checks passed');

