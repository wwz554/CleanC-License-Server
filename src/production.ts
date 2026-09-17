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

async function importSigningKey(env: Env): Promise<CryptoKey> {
  const pem = String(env.LICENSE_SIGNING_PRIVATE_KEY || '');
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

async function maybeReplaceLeaseResponse(
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
  if (!body) return null;
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
  if (initError) return initError;

  const path = new URL(request.url).pathname;

  if (path === '/api/v1/health' && request.method === 'GET') return health();
  if (path === '/api/v1/meta' && request.method === 'GET') return meta(request, env);
  if (path === '/bootstrap/v1/config' && request.method === 'GET') return bootstrap(request, env);

  if (path === '/admin/api/licenses' && request.method === 'POST') {
    const invalid = await validateAdminLicenseCreate(request);
    if (invalid) return invalid;
  }

  if (path === '/api/v1/license/activate' && request.method === 'POST') {
    const body = await readBodyClone(request);
    const response = await handlePagesRequest(request, env);
    return maybeReplaceLeaseResponse(request, env, response, body);
  }

  if (path === '/api/v1/license/refresh' && request.method === 'POST') {
    const body = await readBodyClone(request);
    const response = await handlePagesRequest(request, env);
    return maybeReplaceLeaseResponse(request, env, response, body);
  }

  return handlePagesRequest(request, env);
}
