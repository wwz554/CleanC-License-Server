import { handleAdminTurnstile } from './admin-turnstile';
import { handleAdminPhysicalDelete } from './admin-delete';
import { applyBeijingAdminResponse } from './admin-timezone';
import { handleAppRequest } from './router';
import type { Env } from './worker';

/**
 * 只在管理员登录链路增加 Turnstile。
 * 客户端激活、challenge、refresh 等授权 API 仍直接走原生产路由。
 * 管理后台 JSON 时间统一转换为北京时间显示，授权核心仍使用 UTC。
 */
export async function handleTurnstileAppRequest(request: Request, env: Env): Promise<Response> {
  const path = new URL(request.url).pathname;
  const isAdminLoginPage = (path === '/admin' || path === '/admin/' || path === '/admin/login') && request.method === 'GET';
  const isAdminLoginApi = path === '/admin/api/login' && request.method === 'POST';

  if (isAdminLoginPage || isAdminLoginApi) {
    // 先触发一次现有生产路由初始化，保证 D1 表、索引和运行时保护已经就绪。
    const healthRequest = new Request(new URL('/api/v1/health', request.url), {
      method: 'GET',
      headers: request.headers,
    });
    const health = await handleAppRequest(healthRequest, env);
    if (!health.ok) return health;

    const turnstile = await handleAdminTurnstile(request, env);
    if (turnstile) return turnstile;
  }

  // 物理删除只允许后台管理员发起，并由独立模块做 Session + CSRF 校验。
  const deletion = await handleAdminPhysicalDelete(request, env);
  if (deletion) return deletion;

  const response = await handleAppRequest(request, env);
  return applyBeijingAdminResponse(response, path);
}
