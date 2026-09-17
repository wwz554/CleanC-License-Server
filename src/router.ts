import { handlePagesRequest } from './pages';
import { handleProductionActivation } from './activation';
import { handleProductionRequest } from './production';
import { handlePasswordAdmin, stripTurnstileFromAdminResponse } from './admin-password';
import type { Env } from './worker';

const ROUTER_DB_GUARD_VERSION = '2';
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

function withLegacyAdminCompat(env: Env): Env {
  return {
    ...env,
    // 旧 Pages/Worker 层仍保留 Turnstile 字段检查。
    // 当前生产后台已经由 admin-password.ts 接管，不再实际调用 Turnstile。
    TURNSTILE_SECRET: String(env.TURNSTILE_SECRET || '').trim() || 'password-only-disabled',
    TURNSTILE_SITE_KEY: String(env.TURNSTILE_SITE_KEY || '').trim() || 'password-only-disabled',
  };
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

async function applyRouterDbGuards(env: Env): Promise<void> {
  const current = await env.DB.prepare(
    "SELECT setting_value FROM system_settings WHERE setting_key='ROUTER_DB_GUARD_VERSION'",
  ).first<{ setting_value: string }>();
  if (current?.setting_value === ROUTER_DB_GUARD_VERSION) return;

  // 续期只能延长时间。若管理员之前主动禁用了授权，续期不能在任何瞬间把它重新启用。
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_preserve_disabled_on_renew').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_preserve_disabled_on_renew
    AFTER UPDATE OF expires_at,status ON licenses
    WHEN OLD.status='disabled'
      AND NEW.status='active'
      AND NEW.expires_at IS NOT OLD.expires_at
    BEGIN
      UPDATE licenses SET status='disabled' WHERE id=NEW.id;
    END
  `).run();

  // 与生产热修保持一致：时长授权到期时间允许保持不变或延长，但绝不允许缩短/清空。
  // 这样即使未来基础 schema 升级重新创建了旧 Trigger，最终生产入口仍会恢复正确规则。
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_duration_expiry_monotonic').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_duration_expiry_monotonic
    BEFORE UPDATE OF expires_at ON licenses
    WHEN OLD.license_type='duration'
      AND OLD.activated_at IS NOT NULL
      AND (
        NEW.expires_at IS NULL OR
        (OLD.expires_at IS NOT NULL AND NEW.expires_at < OLD.expires_at)
      )
    BEGIN
      SELECT RAISE(ABORT, 'DURATION_EXPIRY_CAN_ONLY_BE_EXTENDED');
    END
  `).run();

  // 未来即使增加编辑授权的接口，也不允许把时长授权改成非法天数。
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_duration_days_update_guard').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_duration_days_update_guard
    BEFORE UPDATE OF duration_days,license_type ON licenses
    WHEN NEW.license_type='duration'
      AND (NEW.duration_days IS NULL OR NEW.duration_days < 1 OR NEW.duration_days > 36500)
    BEGIN
      SELECT RAISE(ABORT, 'INVALID_DURATION_DAYS');
    END
  `).run();

  // 固定到期授权始终必须有明确到期时间。
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_fixed_expiry_update_guard').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_fixed_expiry_update_guard
    BEFORE UPDATE OF expires_at,license_type ON licenses
    WHEN NEW.license_type='fixed' AND NEW.expires_at IS NULL
    BEGIN
      SELECT RAISE(ABORT, 'FIXED_LICENSE_REQUIRES_EXPIRY');
    END
  `).run();

  await env.DB.prepare(`
    INSERT INTO system_settings(setting_key,setting_value,updated_at)
    VALUES('ROUTER_DB_GUARD_VERSION',?,?)
    ON CONFLICT(setting_key) DO UPDATE SET
      setting_value=excluded.setting_value,
      updated_at=excluded.updated_at
  `).bind(ROUTER_DB_GUARD_VERSION, new Date().toISOString()).run();
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

    await applyRouterDbGuards(env);
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

async function routeRenewal(request: Request, env: Env): Promise<Response> {
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

  // 数据库触发器会原子保持 disabled；这里再做一层应用层保险。
  if (response.ok && before?.status === 'disabled') {
    await env.DB.prepare(
      "UPDATE licenses SET status='disabled' WHERE id=? AND status='active'",
    ).bind(licenseId).run();
  }
  return response;
}

export async function handleAppRequest(request: Request, env: Env): Promise<Response> {
  // 新生产后台不再依赖 Turnstile。这里给旧内部兼容层补占位值，
  // 因此 Cloudflare 可以删除 TURNSTILE_SITE_KEY / TURNSTILE_SECRET。
  const runtimeEnv = withLegacyAdminCompat(env);

  const initError = await ensureRuntime(request, runtimeEnv);
  if (initError) return initError.clone();

  const path = new URL(request.url).pathname;

  const adminResponse = await handlePasswordAdmin(request, runtimeEnv);
  if (adminResponse) return adminResponse;

  if (path === '/api/v1/license/activate' && request.method === 'POST') {
    return handleProductionActivation(request, runtimeEnv);
  }

  if ((path === '/api/v1/device/challenge' || path === '/api/v1/license/refresh') && request.method === 'POST') {
    return routeRenewal(request, runtimeEnv);
  }

  const renew = path.match(/^\/admin\/api\/licenses\/([^/]+)\/renew$/);
  if (renew && request.method === 'POST') {
    return routeAdminRenew(request, runtimeEnv, renew[1]);
  }

  const response = await handleProductionRequest(request, runtimeEnv);
  if ((path === '/admin' || path === '/admin/' || path === '/admin/login') && request.method === 'GET') {
    return stripTurnstileFromAdminResponse(response);
  }
  return response;
}
