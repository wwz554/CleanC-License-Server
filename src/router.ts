import { handlePagesRequest } from './pages';
import { handleProductionActivation } from './activation';
import { handleProductionRequest } from './production';
import type { Env } from './worker';

let runtimeReady: Promise<Response | null> | null = null;

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
}

async function consumeRateLimit(env: Env, key: string, max: number, seconds: number): Promise<boolean> {
  const current = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(`
    INSERT INTO rate_limits(bucket_key,count,window_start) VALUES(?,1,?)
    ON CONFLICT(bucket_key) DO UPDATE SET
      count=CASE WHEN ?-window_start>=? THEN 1 ELSE count+1 END,
      window_start=CASE WHEN ?-window_start>=? THEN ? ELSE window_start END
    RETURNING count
  `).bind(key, current, current, seconds, current, seconds, current).first<{ count: number }>();
  return !!row && row.count <= max;
}

async function ensureRuntime(request: Request, env: Env): Promise<Response | null> {
  if (runtimeReady) return runtimeReady;

  runtimeReady = (async () => {
    // 先让原 Pages 层完成 D1 自动建表与配置检查。
    // 如果这里出现临时错误，本层会清空缓存，下一个请求会自动重试，不会让当前 isolate 永久卡死。
    const healthRequest = new Request(new URL('/api/v1/health', request.url), { method: 'GET' });
    const core = await handlePagesRequest(healthRequest, env);
    if (!core.ok) return core;

    // 再让生产网关执行数据库热修复和协议初始化。
    const production = await handleProductionRequest(healthRequest, env);
    if (!production.ok) return production;
    return null;
  })().catch(error => {
    console.error('Runtime initialization failed', error);
    return json({
      success: false,
      code: 'RUNTIME_INIT_FAILED',
      message: '授权服务初始化失败，请稍后重试。',
    }, 500);
  });

  const result = await runtimeReady;
  if (result) runtimeReady = null;
  return result;
}

async function routeRenewal(request: Request, env: Env, path: string): Promise<Response> {
  let body: Record<string, unknown> | null = null;
  try {
    body = await request.clone().json() as Record<string, unknown>;
  } catch {
    // 交给生产处理器返回统一 INVALID_JSON。
  }

  const deviceId = String(body?.deviceId || '').trim();
  const realIp = request.headers.get('cf-connecting-ip') || 'unknown';

  // NAT 场景只做宽松的真实公网 IP 总限流，避免企业/校园/运营商出口下几十台设备同时续租被误伤。
  if (!await consumeRateLimit(env, `renewal-ip:${realIp}`, 600, 60)) {
    return json({ success: false, code: 'RATE_LIMITED', message: '当前网络续期请求过多，请稍后重试' }, 429);
  }

  if (!deviceId || deviceId.length > 200) {
    return handleProductionRequest(request, env);
  }

  // 生产网关内部仍保留 30 次/分钟保护；这里把其作用域缩小到“单设备”，
  // 这样共享同一公网 IP 的客户互不影响，同时单设备仍无法高频刷接口。
  const headers = new Headers(request.headers);
  headers.set('cf-connecting-ip', `${realIp}|${deviceId}`);
  const scoped = new Request(request, { headers });
  return handleProductionRequest(scoped, env);
}

async function routeAdminRenew(request: Request, env: Env, licenseId: string): Promise<Response> {
  const before = await env.DB.prepare(
    'SELECT status FROM licenses WHERE id=? AND deleted_at IS NULL',
  ).bind(licenseId).first<{ status: string }>();

  const response = await handleProductionRequest(request, env);

  // “续期”只延长时间，不改变管理员主动禁用的状态。
  // 原实现会把 disabled 自动改回 active，这会违背管理员意图。
  if (response.ok && before?.status === 'disabled') {
    await env.DB.prepare(
      "UPDATE licenses SET status='disabled' WHERE id=? AND status='active'",
    ).bind(licenseId).run();
  }
  return response;
}

export async function handleAppRequest(request: Request, env: Env): Promise<Response> {
  const initError = await ensureRuntime(request, env);
  if (initError) return initError.clone();

  const path = new URL(request.url).pathname;

  if (path === '/api/v1/license/activate' && request.method === 'POST') {
    return handleProductionActivation(request, env);
  }

  if ((path === '/api/v1/device/challenge' || path === '/api/v1/license/refresh') && request.method === 'POST') {
    return routeRenewal(request, env, path);
  }

  const renew = path.match(/^\/admin\/api\/licenses\/([^/]+)\/renew$/);
  if (renew && request.method === 'POST') {
    return routeAdminRenew(request, env, renew[1]);
  }

  return handleProductionRequest(request, env);
}
