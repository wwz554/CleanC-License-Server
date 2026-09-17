import type { Env } from './types';
import {
  audit,
  boundedText,
  canonicalBaseUrl,
  configuredBootstrapUrl,
  createSession,
  csrfToken,
  fail,
  getSetting,
  json,
  normalizeHttpsOrigin,
  nowIso,
  optionalText,
  positiveInt,
  randomLicenseKey,
  rateLimit,
  readJson,
  requireAdmin,
  safeEqual,
  SESSION_COOKIE,
  validCustomLicenseKey,
  validDate,
  verifyTurnstile,
  uuid,
} from './common';

export async function login(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(env, `login:${ip}`, 5, 60)) return fail('RATE_LIMITED', '登录尝试过多，请稍后再试', 429);
  const body = await readJson(req);
  const password = boundedText(body.password, 512, false);
  const token = boundedText(body.turnstileToken, 4096, false);
  const passwordOk = !!password && safeEqual(password, env.ADMIN_PASSWORD);
  const turnstileOk = await verifyTurnstile(req, env, token);
  if (!passwordOk || !turnstileOk) {
    await audit(env, req, 'ADMIN_LOGIN_FAILED');
    return fail('LOGIN_FAILED', '密码或验证码错误', 403);
  }
  await audit(env, req, 'ADMIN_LOGIN_SUCCESS');
  return json({ success: true }, 200, {
    'set-cookie': `${SESSION_COOKIE}=${await createSession(env)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,
  });
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

export async function adminApi(req: Request, env: Env, path: string): Promise<Response> {
  const write = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  if (!await requireAdmin(req, env, write)) {
    return fail(write ? 'CSRF_OR_AUTH_FAILED' : 'UNAUTHORIZED', '未授权', write ? 403 : 401);
  }

  if (path === '/admin/api/session' && req.method === 'GET') {
    return json({ success: true, csrfToken: await csrfToken(req, env) });
  }
  if (path === '/admin/api/logout' && req.method === 'POST') {
    return json({ success: true }, 200, {
      'set-cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
    });
  }

  if (path === '/admin/api/dashboard' && req.method === 'GET') {
    const now = nowIso();
    const licenses = await env.DB.prepare(`SELECT
        COUNT(*) total,
        SUM(CASE WHEN status='active' AND (expires_at IS NULL OR expires_at>?) THEN 1 ELSE 0 END) active,
        SUM(CASE WHEN status='disabled' THEN 1 ELSE 0 END) disabled,
        SUM(CASE WHEN expires_at IS NOT NULL AND expires_at<=? THEN 1 ELSE 0 END) expired
      FROM licenses WHERE deleted_at IS NULL`)
      .bind(now, now).first<{ total: number; active: number; disabled: number; expired: number }>();
    const devices = await env.DB.prepare('SELECT COUNT(*) c FROM devices WHERE revoked_at IS NULL').first<{ c: number }>();
    return json({
      success: true,
      stats: {
        total: licenses?.total || 0,
        active: licenses?.active || 0,
        disabled: licenses?.disabled || 0,
        expired: licenses?.expired || 0,
        devices: devices?.c || 0,
      },
    });
  }

  if (path === '/admin/api/licenses' && req.method === 'GET') {
    const { results } = await env.DB.prepare(`SELECT l.*,
      (SELECT COUNT(*) FROM devices d WHERE d.license_id=l.id AND d.revoked_at IS NULL) device_count
      FROM licenses l WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 500`).all();
    return json({ success: true, licenses: results });
  }

  if (path === '/admin/api/licenses' && req.method === 'POST') {
    const body = await readJson(req);
    const count = positiveInt(body.count, 1, 15);
    const maxDevices = positiveInt(body.maxDevices, 1, 1000);
    if (!count || !maxDevices) return fail('INVALID_NUMBER', '数量必须为 1-15，设备上限必须为 1-1000');

    const requestedType = String(body.licenseType || 'permanent');
    const type = ['permanent', 'duration', 'fixed'].includes(requestedType) ? requestedType : null;
    if (!type) return fail('INVALID_LICENSE_TYPE', '授权类型无效');
    const durationDays = type === 'duration' ? positiveInt(body.durationDays, 365, 36500) : null;
    if (type === 'duration' && !durationDays) return fail('INVALID_DURATION', '有效天数必须为 1-36500 的整数');
    const expiresAt = type === 'fixed' ? validDate(body.expiresAt) : null;
    if (type === 'fixed' && (!expiresAt || new Date(expiresAt).getTime() <= Date.now())) {
      return fail('INVALID_EXPIRES_AT', '固定到期时间必须是未来时间');
    }

    const customKey = boundedText(body.licenseKey, 80);
    if (count > 1 && customKey) return fail('CUSTOM_KEY_BATCH_NOT_ALLOWED', '批量生成时不能指定单个自定义授权码');
    if (customKey && !validCustomLicenseKey(customKey)) return fail('INVALID_LICENSE_KEY', '自定义授权码仅允许 6-80 位字母、数字、下划线和短横线');
    if (customKey && await env.DB.prepare('SELECT id FROM licenses WHERE license_key=?').bind(customKey).first()) {
      return fail('LICENSE_KEY_EXISTS', '授权码已存在', 409);
    }

    const edition = boundedText(body.edition ?? 'pro', 32) || 'pro';
    if (!/^[A-Za-z0-9._-]{1,32}$/.test(edition)) return fail('INVALID_EDITION', '版本标识格式无效');
    const note = optionalText(body.note, 500);
    const created: string[] = [];
    const generated = new Set<string>();
    const statements: D1PreparedStatement[] = [];
    const time = nowIso();

    for (let i = 0; i < count; i++) {
      let key = customKey;
      if (!key) {
        do { key = randomLicenseKey(); } while (generated.has(key));
      }
      generated.add(key);
      const id = uuid();
      created.push(key);
      statements.push(
        env.DB.prepare(`INSERT INTO licenses(
          id,license_key,edition,status,license_type,duration_days,expires_at,activated_at,max_devices,note,created_at,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
          .bind(id, key, edition, 'active', type, durationDays, expiresAt, null, maxDevices, note, time, time),
      );
      statements.push(
        env.DB.prepare('INSERT INTO audit_logs(id,event_type,ip,license_id,device_id,detail,created_at) VALUES(?,?,?,?,?,?,?)')
          .bind(uuid(), count > 1 ? 'LICENSE_BATCH_CREATED' : 'LICENSE_CREATED', req.headers.get('cf-connecting-ip'), id, null, JSON.stringify({ licenseKey: key, licenseType: type, durationDays }), time),
      );
    }

    try {
      await env.DB.batch(statements);
    } catch (error) {
      console.error('license create failed', error);
      return fail('LICENSE_CREATE_FAILED', '授权码创建失败，请重试', 409);
    }
    return json({ success: true, licenseKeys: created });
  }

  const licenseAction = path.match(/^\/admin\/api\/licenses\/([^/]+)\/(disable|enable)$/);
  if (licenseAction && req.method === 'POST') {
    const id = licenseAction[1];
    const action = licenseAction[2];
    const license = await env.DB.prepare('SELECT id,status,expires_at FROM licenses WHERE id=? AND deleted_at IS NULL')
      .bind(id).first<{ id: string; status: string; expires_at: string | null }>();
    if (!license) return fail('LICENSE_NOT_FOUND', '授权不存在', 404);
    if (action === 'enable' && license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) {
      return fail('LICENSE_EXPIRED', '授权已经到期，不能恢复为有效状态', 409);
    }
    const status = action === 'disable' ? 'disabled' : 'active';
    await env.DB.prepare('UPDATE licenses SET status=?,updated_at=? WHERE id=?').bind(status, nowIso(), id).run();
    await audit(env, req, status === 'disabled' ? 'LICENSE_DISABLED' : 'LICENSE_ENABLED', null, id);
    return json({ success: true });
  }

  if (path === '/admin/api/devices' && req.method === 'GET') {
    const { results } = await env.DB.prepare(`SELECT d.*,l.license_key
      FROM devices d JOIN licenses l ON l.id=d.license_id
      ORDER BY d.last_seen_at DESC LIMIT 500`).all();
    return json({ success: true, devices: results });
  }

  const deviceRevoke = path.match(/^\/admin\/api\/devices\/([^/]+)\/revoke$/);
  if (deviceRevoke && req.method === 'POST') {
    const result = await env.DB.prepare('UPDATE devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL')
      .bind(nowIso(), deviceRevoke[1]).run();
    if (!result.meta.changes) return fail('DEVICE_NOT_FOUND', '设备不存在或已解绑', 404);
    await audit(env, req, 'DEVICE_REVOKED', { id: deviceRevoke[1] });
    return json({ success: true });
  }

  if (path === '/admin/api/logs' && req.method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500').all();
    return json({ success: true, logs: results });
  }

  if (path === '/admin/api/settings' && req.method === 'GET') {
    return json({
      success: true,
      currentOrigin: new URL(req.url).origin,
      bootstrapBaseUrl: configuredBootstrapUrl(req, env),
      canonicalBaseUrl: await canonicalBaseUrl(req, env),
      turnstileSiteKey: env.TURNSTILE_SITE_KEY || '',
    });
  }

  if (path === '/admin/api/settings/domain' && req.method === 'POST') {
    const body = await readJson(req);
    const password = boundedText(body.password, 512, false);
    const token = boundedText(body.turnstileToken, 4096, false);
    if (!password || !safeEqual(password, env.ADMIN_PASSWORD) || !await verifyTurnstile(req, env, token)) {
      return fail('REAUTH_FAILED', '二次验证失败', 403);
    }
    const requested = boundedText(body.baseUrl, 512);
    const next = normalizeHttpsOrigin(requested);
    if (!next) return fail('INVALID_DOMAIN', '域名格式不正确，只允许标准公网 HTTPS 域名且不允许自定义端口');
    if (!await testCanonicalDomain(next)) return fail('DOMAIN_NOT_READY', '域名尚未正确绑定到此 CleanC Pages 项目', 400);
    const old = await getSetting(env, 'PRIMARY_BASE_URL');
    const time = nowIso();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO system_settings(setting_key,setting_value,updated_at) VALUES('PRIMARY_BASE_URL',?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at")
        .bind(next, time),
      env.DB.prepare('INSERT INTO domain_history(id,old_url,new_url,ip,created_at) VALUES(?,?,?,?,?)')
        .bind(uuid(), old, next, req.headers.get('cf-connecting-ip'), time),
    ]);
    await audit(env, req, 'DOMAIN_CHANGED', { old, next });
    return json({ success: true, canonicalBaseUrl: next });
  }

  if (path === '/admin/api/settings/domain/rollback' && req.method === 'POST') {
    const body = await readJson(req);
    const password = boundedText(body.password, 512, false);
    const token = boundedText(body.turnstileToken, 4096, false);
    if (!password || !safeEqual(password, env.ADMIN_PASSWORD) || !await verifyTurnstile(req, env, token)) {
      return fail('REAUTH_FAILED', '二次验证失败', 403);
    }
    const fallback = normalizeHttpsOrigin(env.BOOTSTRAP_BASE_URL || '');
    if (!fallback) return fail('BOOTSTRAP_NOT_CONFIGURED', 'BOOTSTRAP_BASE_URL 未正确配置，无法安全回退', 500);
    const old = await getSetting(env, 'PRIMARY_BASE_URL');
    await env.DB.prepare("DELETE FROM system_settings WHERE setting_key='PRIMARY_BASE_URL'").run();
    await audit(env, req, 'DOMAIN_ROLLBACK', { old, next: fallback });
    return json({ success: true, canonicalBaseUrl: fallback });
  }

  return fail('NOT_FOUND', '接口不存在', 404);
}
