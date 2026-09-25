import { handlePagesRequest } from './pages';
import type { Env } from './worker';

const API_VERSION = 3;
const LEASE_VERSION = 4;
const HOTFIX_VERSION = '1';
const encoder = new TextEncoder();
let initPromise: Promise<Response | null> | null = null;
let signingKeyCache: { pem: string; promise: Promise<CryptoKey> } | null = null;

type LicenseRecord = {
  id: string;
  license_key: string;
  edition: string;
  status: string;
  license_type: 'permanent' | 'duration' | 'fixed';
  duration_days: number | null;
  expires_at: string | null;
  activated_at: string | null;
};

type ActiveDevice = {
  id: string;
  license_id: string;
  device_id: string;
  public_key: string | null;
};

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
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

async function getSetting(env: Env, key: string): Promise<string | null> {
  return (await env.DB.prepare(
    'SELECT setting_value FROM system_settings WHERE setting_key=?',
  ).bind(key).first<{ setting_value: string }>())?.setting_value || null;
}

async function setSetting(env: Env, key: string, value: string): Promise<void> {
  await env.DB.prepare(`
    INSERT INTO system_settings(setting_key,setting_value,updated_at)
    VALUES(?,?,?)
    ON CONFLICT(setting_key) DO UPDATE SET
      setting_value=excluded.setting_value,
      updated_at=excluded.updated_at
  `).bind(key, value, new Date().toISOString()).run();
}

function bootstrapBaseUrl(request: Request, env: Env): string {
  const configured = String(env.BOOTSTRAP_BASE_URL || '').trim().replace(/\/$/, '');
  return configured || new URL(request.url).origin;
}

async function canonicalBaseUrl(request: Request, env: Env): Promise<string> {
  return (await getSetting(env, 'PRIMARY_BASE_URL')) || bootstrapBaseUrl(request, env);
}

function leaseHours(env: Env): number {
  const value = Number(env.LEASE_HOURS || 72);
  return Number.isFinite(value) ? Math.max(1, Math.min(value, 720)) : 72;
}

function isExpired(license: LicenseRecord, now = Date.now()): boolean {
  return !!license.expires_at && new Date(license.expires_at).getTime() <= now;
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

async function importSigningKey(env: Env): Promise<CryptoKey> {
  const pem = normalizePem(String(env.LICENSE_SIGNING_PRIVATE_KEY || ''));
  if (signingKeyCache?.pem === pem) return signingKeyCache.promise;
  const raw = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+/g, '');
  if (!raw) throw new Error('SIGNING_KEY_MISSING');
  const promise = crypto.subtle.importKey(
    'pkcs8',
    Uint8Array.from(atob(raw), c => c.charCodeAt(0)),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  signingKeyCache = { pem, promise };
  return promise;
}

async function signObject(env: Env, value: Record<string, unknown>): Promise<{ signedPayload: string; signature: string }> {
  const serialized = JSON.stringify(value);
  const key = await importSigningKey(env);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    encoder.encode(serialized),
  );
  return {
    signedPayload: b64url(encoder.encode(serialized)),
    signature: b64url(signature),
  };
}

async function verifyDeviceSignature(publicKeyPem: string, nonce: string, signature: string): Promise<boolean> {
  try {
    const raw = publicKeyPem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
    if (!raw) return false;
    const publicKey = await crypto.subtle.importKey(
      'spki',
      Uint8Array.from(atob(raw), c => c.charCodeAt(0)),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      unb64url(signature),
      encoder.encode(nonce),
    );
  } catch {
    return false;
  }
}

async function applyProductionHotfixes(env: Env): Promise<void> {
  if (await getSetting(env, 'PRODUCTION_GATEWAY_HOTFIX_VERSION') === HOTFIX_VERSION) return;

  // 修复：时长授权重新绑定同一到期时间时，不应被错误判定为“缩短到期时间”。
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

  // 生产保险：授权类型只能是三种明确值，绝不允许错误值被默认为永久授权。
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_license_type_insert_guard').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_license_type_insert_guard
    BEFORE INSERT ON licenses
    WHEN NEW.license_type NOT IN ('permanent','duration','fixed')
    BEGIN
      SELECT RAISE(ABORT, 'INVALID_LICENSE_TYPE');
    END
  `).run();
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_license_type_update_guard').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_license_type_update_guard
    BEFORE UPDATE OF license_type ON licenses
    WHEN NEW.license_type NOT IN ('permanent','duration','fixed')
    BEGIN
      SELECT RAISE(ABORT, 'INVALID_LICENSE_TYPE');
    END
  `).run();

  // 永久授权必须没有总到期时间；防止后台或未来代码误写 expires_at。
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_permanent_no_expiry_insert').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_permanent_no_expiry_insert
    BEFORE INSERT ON licenses
    WHEN NEW.license_type='permanent' AND NEW.expires_at IS NOT NULL
    BEGIN
      SELECT RAISE(ABORT, 'PERMANENT_LICENSE_CANNOT_EXPIRE');
    END
  `).run();
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_permanent_no_expiry_update').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_permanent_no_expiry_update
    BEFORE UPDATE OF expires_at,license_type ON licenses
    WHEN NEW.license_type='permanent' AND NEW.expires_at IS NOT NULL
    BEGIN
      SELECT RAISE(ABORT, 'PERMANENT_LICENSE_CANNOT_EXPIRE');
    END
  `).run();

  // 时长授权必须有合法天数；固定到期授权必须有明确到期时间。
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_duration_days_guard').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_duration_days_guard
    BEFORE INSERT ON licenses
    WHEN NEW.license_type='duration'
      AND (NEW.duration_days IS NULL OR NEW.duration_days < 1 OR NEW.duration_days > 36500)
    BEGIN
      SELECT RAISE(ABORT, 'INVALID_DURATION_DAYS');
    END
  `).run();
  await env.DB.prepare('DROP TRIGGER IF EXISTS trg_fixed_expiry_guard').run();
  await env.DB.prepare(`
    CREATE TRIGGER trg_fixed_expiry_guard
    BEFORE INSERT ON licenses
    WHEN NEW.license_type='fixed' AND NEW.expires_at IS NULL
    BEGIN
      SELECT RAISE(ABORT, 'FIXED_LICENSE_REQUIRES_EXPIRY');
    END
  `).run();

  await setSetting(env, 'PRODUCTION_GATEWAY_HOTFIX_VERSION', HOTFIX_VERSION);
}

async function initialize(request: Request, env: Env): Promise<Response | null> {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    // 用内部 health 请求触发原有 D1 自动建表与生产配置检查，但不暴露旧 apiVersion。
    const internalRequest = new Request(new URL('/api/v1/health', request.url), { method: 'GET' });
    const coreResponse = await handlePagesRequest(internalRequest, env);
    if (!coreResponse.ok) return coreResponse;
    await applyProductionHotfixes(env);
    return null;
  })().catch(error => {
    initPromise = null;
    console.error('Production gateway initialization failed', error);
    return json({
      success: false,
      code: 'PRODUCTION_INIT_FAILED',
      message: '生产授权网关初始化失败，请检查 D1 与 Pages 配置。',
    }, 500);
  });
  return initPromise;
}

async function loadLicense(env: Env, licenseKey: string): Promise<LicenseRecord | null> {
  return env.DB.prepare(`
    SELECT id,license_key,edition,status,license_type,duration_days,expires_at,activated_at
    FROM licenses
    WHERE license_key=? AND deleted_at IS NULL
  `).bind(licenseKey).first<LicenseRecord>();
}

async function loadActiveDevice(env: Env, licenseId: string, deviceId: string): Promise<ActiveDevice | null> {
  return env.DB.prepare(`
    SELECT id,license_id,device_id,public_key
    FROM devices
    WHERE license_id=? AND device_id=? AND revoked_at IS NULL
  `).bind(licenseId, deviceId).first<ActiveDevice>();
}

async function issueProductionLease(
  request: Request,
  env: Env,
  license: LicenseRecord,
  deviceId: string,
): Promise<Response> {
  const now = Date.now();
  const hours = leaseHours(env);
  const leaseLimit = now + hours * 3600_000;
  const totalLimit = license.expires_at ? new Date(license.expires_at).getTime() : Number.POSITIVE_INFINITY;
  if (!Number.isFinite(totalLimit) && license.expires_at) {
    return json({ success: false, code: 'INVALID_LICENSE_EXPIRY', message: '授权到期时间异常，请联系管理员。' }, 500);
  }
  const permanent = license.license_type === 'permanent';
  const lease = {
    version: LEASE_VERSION,
    apiVersion: API_VERSION,
    licenseId: license.id,
    deviceId,
    edition: license.edition,
    licenseType: license.license_type,
    isPermanent: permanent,
    displayText: permanent ? '永久授权' : null,
    countdownRequired: !permanent,
    features: ['clean', 'scan', 'optimize'],
    issuedAt: new Date(now).toISOString(),
    serverTime: new Date(now).toISOString(),
    expiresAt: new Date(Math.min(leaseLimit, totalLimit)).toISOString(),
    licenseExpiresAt: license.expires_at,
    leaseHours: hours,
    renewalProtocol: 'challenge-refresh',
    singleDeviceLicense: true,
    nonce: crypto.randomUUID(),
  } satisfies Record<string, unknown>;
  const signed = await signObject(env, lease);
  return json({
    success: true,
    lease,
    ...signed,
    canonicalBaseUrl: await canonicalBaseUrl(request, env),
  });
}

async function readBodyClone(request: Request): Promise<Record<string, unknown> | null> {
  try {
    return await request.clone().json() as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function maybeReplaceActivationLease(
  request: Request,
  env: Env,
  coreResponse: Response,
  body: Record<string, unknown> | null,
): Promise<Response> {
  if (!coreResponse.ok || !body) return coreResponse;
  let payload: { success?: boolean } | null = null;
  try {
    payload = await coreResponse.clone().json() as { success?: boolean };
  } catch {
    return coreResponse;
  }
  if (payload?.success !== true) return coreResponse;

  const licenseKey = String(body.licenseKey || '').trim();
  const deviceId = String(body.deviceId || '').trim();
  if (!licenseKey || !deviceId) return coreResponse;
  const license = await loadLicense(env, licenseKey);
  if (!license) return coreResponse;
  return issueProductionLease(request, env, license, deviceId);
}

async function validateAdminLicenseCreate(request: Request): Promise<Response | null> {
  const body = await readBodyClone(request);
  if (!body) {
    return json({ success: false, code: 'INVALID_JSON', message: '授权创建请求不是有效 JSON。' }, 400);
  }
  const type = String(body.licenseType || '');
  if (!['permanent', 'duration', 'fixed'].includes(type)) {
    return json({
      success: false,
      code: 'INVALID_LICENSE_TYPE',
      message: '授权类型无效，只允许：永久、激活后 N 天、固定到期。',
    }, 400);
  }
  return null;
}

async function handleProductionChallenge(request: Request, env: Env): Promise<Response> {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (!await consumeRateLimit(env, `challenge:${ip}`, 30, 60)) {
    return json({ success: false, code: 'RATE_LIMITED', message: '请求过于频繁' }, 429);
  }
  const body = await readBodyClone(request);
  if (!body) return json({ success: false, code: 'INVALID_JSON', message: '请求格式无效' }, 400);
  const licenseKey = String(body.licenseKey || '').trim();
  const deviceId = String(body.deviceId || '').trim();
  if (!licenseKey || !deviceId || deviceId.length > 200) {
    return json({ success: false, code: 'INVALID_REQUEST', message: '缺少授权码或设备标识' }, 400);
  }

  const license = await loadLicense(env, licenseKey);
  if (!license) return json({ success: false, code: 'LICENSE_NOT_FOUND', message: '授权码不存在' }, 404);
  const device = await loadActiveDevice(env, license.id, deviceId);
  if (!device?.public_key) {
    return json({ success: false, code: 'DEVICE_NOT_BOUND', message: '设备未绑定或已解绑' }, 403);
  }

  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = b64url(nonceBytes);
  const nowIso = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();

  // 只清理已失效 challenge，不删除仍有效的其他 nonce，避免双击/多实例互相使对方 nonce 失效。
  await env.DB.batch([
    env.DB.prepare(`
      DELETE FROM device_challenges
      WHERE license_id=? AND device_id=? AND (expires_at<=? OR used_at IS NOT NULL)
    `).bind(license.id, deviceId, nowIso),
    env.DB.prepare(`
      INSERT INTO device_challenges(id,license_id,device_id,nonce,expires_at,used_at,created_at)
      VALUES(?,?,?,?,?,NULL,?)
    `).bind(crypto.randomUUID(), license.id, deviceId, nonce, expiresAt, nowIso),
  ]);

  return json({
    success: true,
    nonce,
    expiresAt,
    licenseType: license.license_type,
    isPermanent: license.license_type === 'permanent',
    licenseExpiresAt: license.expires_at,
    licenseExpired: isExpired(license),
  });
}

async function handleProductionRefresh(request: Request, env: Env): Promise<Response> {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (!await consumeRateLimit(env, `refresh:${ip}`, 30, 60)) {
    return json({ success: false, code: 'RATE_LIMITED', message: '请求过于频繁' }, 429);
  }
  const body = await readBodyClone(request);
  if (!body) return json({ success: false, code: 'INVALID_JSON', message: '请求格式无效' }, 400);

  const licenseKey = String(body.licenseKey || '').trim();
  const deviceId = String(body.deviceId || '').trim();
  const nonce = String(body.nonce || '').trim();
  const signature = String(body.signature || '').trim();
  if (!licenseKey || !deviceId || !nonce || !signature || deviceId.length > 200 || nonce.length > 256 || signature.length > 1024) {
    return json({ success: false, code: 'INVALID_REQUEST', message: '续期参数无效' }, 400);
  }

  let license = await loadLicense(env, licenseKey);
  if (!license) return json({ success: false, code: 'LICENSE_NOT_FOUND', message: '授权码不存在' }, 404);
  const device = await loadActiveDevice(env, license.id, deviceId);
  if (!device?.public_key) {
    return json({ success: false, code: 'DEVICE_NOT_BOUND', message: '设备未绑定或已解绑，请重新激活' }, 403);
  }

  const challenge = await env.DB.prepare(`
    SELECT id,expires_at
    FROM device_challenges
    WHERE license_id=? AND device_id=? AND nonce=? AND used_at IS NULL
    ORDER BY created_at DESC LIMIT 1
  `).bind(license.id, deviceId, nonce).first<{ id: string; expires_at: string }>();
  const now = new Date();
  const nowIso = now.toISOString();
  if (!challenge || new Date(challenge.expires_at).getTime() <= now.getTime()) {
    return json({ success: false, code: 'CHALLENGE_INVALID', message: '设备挑战无效或已过期' }, 403);
  }
  if (!await verifyDeviceSignature(device.public_key, nonce, signature)) {
    return json({ success: false, code: 'INVALID_DEVICE_SIGNATURE', message: '设备签名验证失败' }, 403);
  }

  const used = await env.DB.prepare(`
    UPDATE device_challenges SET used_at=?
    WHERE id=? AND used_at IS NULL AND expires_at>?
  `).bind(nowIso, challenge.id, nowIso).run();
  if (!used.meta.changes) {
    return json({ success: false, code: 'CHALLENGE_ALREADY_USED', message: '设备挑战已被使用' }, 409);
  }

  // 验证设备身份后重新读取授权，避免管理员恰好续期时使用旧的“已过期”快照误解绑客户。
  license = await loadLicense(env, licenseKey);
  if (!license) return json({ success: false, code: 'LICENSE_NOT_FOUND', message: '授权码不存在' }, 404);

  if (isExpired(license, now.getTime())) {
    // 原子确认数据库里的当前授权仍然过期，只有条件仍成立才真正释放设备。
    const released = await env.DB.prepare(`
      UPDATE devices
      SET revoked_at=?,last_seen_at=?
      WHERE id=? AND revoked_at IS NULL
        AND EXISTS(
          SELECT 1 FROM licenses
          WHERE id=? AND deleted_at IS NULL
            AND expires_at IS NOT NULL
            AND expires_at<=?
        )
    `).bind(nowIso, nowIso, device.id, license.id, nowIso).run();

    if (released.meta.changes) {
      return json({
        success: false,
        code: 'LICENSE_EXPIRED_RELEASED',
        message: '授权已到期，旧设备绑定已安全释放。现在可以激活新的授权码；如果管理员已为原授权码续期，也可以重新使用原授权码激活。',
        licenseExpiresAt: license.expires_at,
        deviceReleased: true,
        canActivateNewLicense: true,
      }, 403);
    }

    // 如果条件更新没有发生，可能是管理员刚刚续期；再次读取后按最新状态处理。
    license = await loadLicense(env, licenseKey);
    if (!license) return json({ success: false, code: 'LICENSE_NOT_FOUND', message: '授权码不存在' }, 404);
    const stillActive = await loadActiveDevice(env, license.id, deviceId);
    if (!stillActive) {
      return json({ success: false, code: 'DEVICE_NOT_BOUND', message: '设备绑定已被释放，请重新激活' }, 403);
    }
    if (isExpired(license)) {
      return json({ success: false, code: 'LICENSE_EXPIRED', message: '授权已过期，请重新发起续期或联系管理员' }, 403);
    }
  }

  if (license.status.toLowerCase() !== 'active') {
    return json({ success: false, code: 'LICENSE_DISABLED', message: '授权已被管理员禁用' }, 403);
  }

  const updated = await env.DB.prepare(`
    UPDATE devices
    SET last_seen_at=?,app_version=COALESCE(?,app_version),windows_version=COALESCE(?,windows_version)
    WHERE id=? AND revoked_at IS NULL
  `).bind(
    new Date().toISOString(),
    body.appVersion ? String(body.appVersion).slice(0, 100) : null,
    body.windowsVersion ? String(body.windowsVersion).slice(0, 200) : null,
    device.id,
  ).run();
  if (!updated.meta.changes) {
    return json({ success: false, code: 'DEVICE_NOT_BOUND', message: '设备已被管理员解绑，请重新激活' }, 403);
  }

  return issueProductionLease(request, env, license, deviceId);
}

async function health(): Promise<Response> {
  return json({
    status: 'ok',
    service: 'cleanc-license-server',
    apiVersion: API_VERSION,
    leaseVersion: LEASE_VERSION,
    renewalProtocol: 'challenge-refresh',
    singleDeviceLicense: true,
  });
}

async function meta(request: Request, env: Env): Promise<Response> {
  return json({
    appName: env.APP_NAME || 'CleanC',
    apiVersion: API_VERSION,
    leaseVersion: LEASE_VERSION,
    canonicalBaseUrl: await canonicalBaseUrl(request, env),
    leaseHours: leaseHours(env),
    renewalProtocol: 'challenge-refresh',
    singleDeviceLicense: true,
    permanentDisplayText: '永久授权',
  });
}

async function bootstrap(request: Request, env: Env): Promise<Response> {
  const payload = {
    apiVersion: API_VERSION,
    leaseVersion: LEASE_VERSION,
    canonicalBaseUrl: await canonicalBaseUrl(request, env),
    issuedAt: new Date().toISOString(),
    leaseHours: leaseHours(env),
    renewalProtocol: 'challenge-refresh',
    singleDeviceLicense: true,
    permanentDisplayText: '永久授权',
  } satisfies Record<string, unknown>;
  return json({ ...payload, ...await signObject(env, payload) });
}

export async function handleProductionRequest(request: Request, env: Env): Promise<Response> {
  const initError = await initialize(request, env);
  if (initError) return initError.clone();

  const path = new URL(request.url).pathname;

  if (path === '/api/v1/health' && request.method === 'GET') return health();
  if (path === '/api/v1/meta' && request.method === 'GET') return meta(request, env);
  if (path === '/bootstrap/v1/config' && request.method === 'GET') return bootstrap(request, env);

  if (path === '/admin/api/licenses' && request.method === 'POST') {
    const invalid = await validateAdminLicenseCreate(request);
    if (invalid) return invalid;
  }

  if (path === '/api/v1/device/challenge' && request.method === 'POST') {
    return handleProductionChallenge(request, env);
  }

  if (path === '/api/v1/license/refresh' && request.method === 'POST') {
    return handleProductionRefresh(request, env);
  }

  if (path === '/api/v1/license/activate' && request.method === 'POST') {
    const body = await readBodyClone(request);
    const response = await handlePagesRequest(request, env);
    return maybeReplaceActivationLease(request, env, response, body);
  }

  return handlePagesRequest(request, env);
}

import { normalizePem } from './request-json';
