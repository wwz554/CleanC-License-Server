import worker, { type Env } from './worker';

let schemaReady: Promise<void> | null = null;
let signingKeyCache: { pem: string; promise: Promise<CryptoKey> } | null = null;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SCHEMA_VERSION = '4';
const REQUIRED_SECRETS: Array<keyof Env> = [
  'ADMIN_PASSWORD',
  'SESSION_SECRET',
  'TURNSTILE_SECRET',
  'LICENSE_SIGNING_PRIVATE_KEY',
];

type LicenseRecord = {
  id: string;
  license_key: string;
  edition: string;
  status: string;
  license_type: string;
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

function apiJson(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
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

function safeEqual(a: string, b: string): boolean {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
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
    .find(value => value.startsWith(`${name}=`))
    ?.slice(name.length + 1) || '';
}

async function validAdminWrite(request: Request, env: Env): Promise<boolean> {
  const session = getCookie(request, 'cleanc_session');
  const [payload, signature] = session.split('.');
  if (!payload || !signature) return false;
  if (!safeEqual(signature, await hmac(env.SESSION_SECRET, payload))) return false;
  try {
    const parsed = JSON.parse(decoder.decode(unb64url(payload))) as { exp?: number };
    if (typeof parsed.exp !== 'number' || parsed.exp <= Date.now()) return false;
  } catch {
    return false;
  }
  const expectedCsrf = await hmac(env.SESSION_SECRET, `csrf:${session}`);
  return safeEqual(request.headers.get('x-csrf-token') || '', expectedCsrf);
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

function configuredBootstrapUrl(request: Request, env: Env): string {
  const configured = String(env.BOOTSTRAP_BASE_URL || '').trim().replace(/\/$/, '');
  return configured || new URL(request.url).origin;
}

async function canonicalBaseUrl(request: Request, env: Env): Promise<string> {
  return (await getSetting(env, 'PRIMARY_BASE_URL')) || configuredBootstrapUrl(request, env);
}

async function audit(
  env: Env,
  request: Request,
  eventType: string,
  detail: unknown = null,
  licenseId: string | null = null,
  deviceId: string | null = null,
): Promise<void> {
  await env.DB.prepare(`
    INSERT INTO audit_logs(id,event_type,ip,license_id,device_id,detail,created_at)
    VALUES(?,?,?,?,?,?,?)
  `).bind(
    crypto.randomUUID(),
    eventType,
    request.headers.get('cf-connecting-ip'),
    licenseId,
    deviceId,
    detail == null ? null : JSON.stringify(detail),
    new Date().toISOString(),
  ).run();
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

async function runHousekeeping(env: Env): Promise<void> {
  const today = new Date().toISOString().slice(0, 10);
  if (await getSetting(env, 'LAST_HOUSEKEEPING_DATE') === today) return;
  const nowSeconds = Math.floor(Date.now() / 1000);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(nowSeconds - 7 * 86400),
    env.DB.prepare('DELETE FROM device_challenges WHERE expires_at < ? OR used_at IS NOT NULL')
      .bind(new Date(Date.now() - 86400000).toISOString()),
    env.DB.prepare('DELETE FROM activation_locks WHERE locked_until < ?').bind(Date.now() - 60000),
  ]);
  await setSetting(env, 'LAST_HOUSEKEEPING_DATE', today);
}

async function ensureSchema(env: Env): Promise<void> {
  if (!env.DB) throw new Error('D1_BINDING_MISSING');
  if (schemaReady) return schemaReady;

  schemaReady = (async () => {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS system_settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT,
        updated_at TEXT NOT NULL
      )
    `).run();

    const currentVersion = await getSetting(env, 'SCHEMA_VERSION');
    if (currentVersion === SCHEMA_VERSION) {
      await runHousekeeping(env);
      return;
    }

    const tableStatements = [
      `CREATE TABLE IF NOT EXISTS licenses (
        id TEXT PRIMARY KEY,
        license_key TEXT NOT NULL UNIQUE,
        edition TEXT NOT NULL DEFAULT 'pro',
        status TEXT NOT NULL DEFAULT 'active',
        license_type TEXT NOT NULL,
        duration_days INTEGER,
        expires_at TEXT,
        activated_at TEXT,
        max_devices INTEGER NOT NULL DEFAULT 1,
        note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        deleted_at TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        license_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        public_key TEXT,
        device_name TEXT,
        windows_version TEXT,
        app_version TEXT,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        revoked_at TEXT,
        UNIQUE(license_id, device_id)
      )`,
      `CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        ip TEXT,
        license_id TEXT,
        device_id TEXT,
        detail TEXT,
        created_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS domain_history (
        id TEXT PRIMARY KEY,
        old_url TEXT,
        new_url TEXT NOT NULL,
        ip TEXT,
        created_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS device_challenges (
        id TEXT PRIMARY KEY,
        license_id TEXT,
        device_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS rate_limits (
        bucket_key TEXT PRIMARY KEY,
        count INTEGER NOT NULL,
        window_start INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS activation_locks (
        license_key TEXT PRIMARY KEY,
        lock_token TEXT NOT NULL,
        locked_until INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS offline_activation_sessions (
        session_id TEXT PRIMARY KEY,
        request_hash TEXT NOT NULL,
        license_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      )`,
    ];
    for (const sql of tableStatements) await env.DB.prepare(sql).run();

    const challengeColumns = await env.DB.prepare(
      'PRAGMA table_info(device_challenges)',
    ).all<{ name: string }>();
    if (!challengeColumns.results.some(column => column.name === 'license_id')) {
      try {
        await env.DB.prepare('ALTER TABLE device_challenges ADD COLUMN license_id TEXT').run();
      } catch (error) {
        const after = await env.DB.prepare('PRAGMA table_info(device_challenges)').all<{ name: string }>();
        if (!after.results.some(column => column.name === 'license_id')) throw error;
      }
    }

    const cleanupTime = new Date().toISOString();
    await env.DB.prepare('UPDATE licenses SET max_devices=1 WHERE max_devices<>1').run();

    // Migration safety: if an old test database contained multiple active bindings,
    // keep the earliest binding and revoke the rest before adding unique indexes.
    await env.DB.prepare(`
      UPDATE devices AS d
      SET revoked_at=?
      WHERE d.revoked_at IS NULL
        AND EXISTS (
          SELECT 1 FROM devices AS earlier
          WHERE earlier.license_id=d.license_id
            AND earlier.revoked_at IS NULL
            AND (
              earlier.first_seen_at < d.first_seen_at OR
              (earlier.first_seen_at = d.first_seen_at AND earlier.id < d.id)
            )
        )
    `).bind(cleanupTime).run();
    await env.DB.prepare(`
      UPDATE devices AS d
      SET revoked_at=?
      WHERE d.revoked_at IS NULL
        AND EXISTS (
          SELECT 1 FROM devices AS earlier
          WHERE earlier.device_id=d.device_id
            AND earlier.revoked_at IS NULL
            AND (
              earlier.first_seen_at < d.first_seen_at OR
              (earlier.first_seen_at = d.first_seen_at AND earlier.id < d.id)
            )
        )
    `).bind(cleanupTime).run();

    const oldTriggers = [
      'trg_duration_expiry_immutable',
      'trg_device_limit_insert',
      'trg_device_limit_rebind',
      'trg_license_single_device_insert',
      'trg_license_single_device_rebind',
      'trg_device_single_license_insert',
      'trg_device_single_license_rebind',
      'trg_max_devices_insert',
      'trg_max_devices_update',
      'trg_duration_expiry_monotonic',
    ];
    for (const name of oldTriggers) {
      await env.DB.prepare(`DROP TRIGGER IF EXISTS ${name}`).run();
    }

    const indexAndTriggerStatements = [
      `CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)`,
      `CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_id)`,
      `CREATE INDEX IF NOT EXISTS idx_devices_license_active ON devices(license_id, revoked_at)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_challenges_device ON device_challenges(device_id, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_challenges_expiry ON device_challenges(expires_at, used_at)`,
      `CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start)`,
      `CREATE INDEX IF NOT EXISTS idx_activation_locks_until ON activation_locks(locked_until)`,
      `CREATE INDEX IF NOT EXISTS idx_offline_sessions_expiry ON offline_activation_sessions(expires_at, status)`,
      `CREATE INDEX IF NOT EXISTS idx_challenges_license_device ON device_challenges(license_id, device_id, created_at DESC)`,
      `CREATE UNIQUE INDEX IF NOT EXISTS uq_one_active_device_per_license
        ON devices(license_id) WHERE revoked_at IS NULL`,
      `CREATE UNIQUE INDEX IF NOT EXISTS uq_one_active_license_per_device
        ON devices(device_id) WHERE revoked_at IS NULL`,
      `CREATE TRIGGER IF NOT EXISTS trg_duration_license_insert_guard
        BEFORE INSERT ON licenses
        WHEN NEW.license_type='duration' AND (NEW.activated_at IS NOT NULL OR NEW.expires_at IS NOT NULL)
        BEGIN
          SELECT RAISE(ABORT, 'DURATION_LICENSE_MUST_START_UNUSED');
        END`,
      `CREATE TRIGGER IF NOT EXISTS trg_activation_time_immutable
        BEFORE UPDATE OF activated_at ON licenses
        WHEN OLD.activated_at IS NOT NULL AND NEW.activated_at IS NOT OLD.activated_at
        BEGIN
          SELECT RAISE(ABORT, 'ACTIVATION_TIME_IMMUTABLE');
        END`,
      `CREATE TRIGGER IF NOT EXISTS trg_duration_expiry_monotonic
        BEFORE UPDATE OF expires_at ON licenses
        WHEN OLD.license_type='duration'
          AND OLD.activated_at IS NOT NULL
          AND (
            NEW.expires_at IS NULL OR
            (OLD.expires_at IS NOT NULL AND NEW.expires_at <= OLD.expires_at)
          )
        BEGIN
          SELECT RAISE(ABORT, 'DURATION_EXPIRY_CAN_ONLY_BE_EXTENDED');
        END`,
      `CREATE TRIGGER IF NOT EXISTS trg_max_devices_insert
        BEFORE INSERT ON licenses
        WHEN NEW.max_devices<>1
        BEGIN
          SELECT RAISE(ABORT, 'MAX_DEVICES_MUST_BE_ONE');
        END`,
      `CREATE TRIGGER IF NOT EXISTS trg_max_devices_update
        BEFORE UPDATE OF max_devices ON licenses
        WHEN NEW.max_devices<>1
        BEGIN
          SELECT RAISE(ABORT, 'MAX_DEVICES_MUST_BE_ONE');
        END`,
      `CREATE TRIGGER IF NOT EXISTS trg_license_single_device_insert
        BEFORE INSERT ON devices
        WHEN NEW.revoked_at IS NULL
          AND EXISTS(SELECT 1 FROM devices WHERE license_id=NEW.license_id AND revoked_at IS NULL)
        BEGIN
          SELECT RAISE(ABORT, 'LICENSE_ALREADY_BOUND');
        END`,
      `CREATE TRIGGER IF NOT EXISTS trg_license_single_device_rebind
        BEFORE UPDATE OF revoked_at ON devices
        WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL
          AND EXISTS(SELECT 1 FROM devices WHERE license_id=NEW.license_id AND revoked_at IS NULL AND id<>NEW.id)
        BEGIN
          SELECT RAISE(ABORT, 'LICENSE_ALREADY_BOUND');
        END`,
      `CREATE TRIGGER IF NOT EXISTS trg_device_single_license_insert
        BEFORE INSERT ON devices
        WHEN NEW.revoked_at IS NULL
          AND EXISTS(SELECT 1 FROM devices WHERE device_id=NEW.device_id AND revoked_at IS NULL)
        BEGIN
          SELECT RAISE(ABORT, 'DEVICE_ALREADY_BOUND');
        END`,
      `CREATE TRIGGER IF NOT EXISTS trg_device_single_license_rebind
        BEFORE UPDATE OF revoked_at ON devices
        WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL
          AND EXISTS(SELECT 1 FROM devices WHERE device_id=NEW.device_id AND revoked_at IS NULL AND id<>NEW.id)
        BEGIN
          SELECT RAISE(ABORT, 'DEVICE_ALREADY_BOUND');
        END`,
    ];
    for (const sql of indexAndTriggerStatements) await env.DB.prepare(sql).run();

    await setSetting(env, 'SCHEMA_VERSION', SCHEMA_VERSION);
    await runHousekeeping(env);
  })().catch(error => {
    schemaReady = null;
    throw error;
  });

  return schemaReady;
}

function missingProductionConfig(env: Env): string[] {
  const missing: string[] = [];
  for (const key of REQUIRED_SECRETS) {
    if (!String(env[key] || '').trim()) missing.push(String(key));
  }
  if (!String(env.TURNSTILE_SITE_KEY || '').trim()) missing.push('TURNSTILE_SITE_KEY');
  return missing;
}

async function acquireLock(env: Env, lockKey: string): Promise<string | null> {
  const token = crypto.randomUUID();
  const now = Date.now();
  const until = now + 15000;
  const row = await env.DB.prepare(`
    INSERT INTO activation_locks(license_key,lock_token,locked_until)
    VALUES(?,?,?)
    ON CONFLICT(license_key) DO UPDATE SET
      lock_token=excluded.lock_token,
      locked_until=excluded.locked_until
    WHERE activation_locks.locked_until < ?
    RETURNING lock_token
  `).bind(lockKey, token, until, now).first<{ lock_token: string }>();
  return row?.lock_token === token ? token : null;
}

async function releaseLock(env: Env, lockKey: string, token: string): Promise<void> {
  try {
    await env.DB.prepare(
      'DELETE FROM activation_locks WHERE license_key=? AND lock_token=?',
    ).bind(lockKey, token).run();
  } catch (error) {
    console.error('Failed to release activation lock', error);
  }
}

async function loadLicense(env: Env, key: string): Promise<LicenseRecord | null> {
  return env.DB.prepare(`
    SELECT id,license_key,edition,status,license_type,duration_days,expires_at,activated_at
    FROM licenses
    WHERE license_key=? AND deleted_at IS NULL
  `).bind(key).first<LicenseRecord>();
}

function isExpired(license: LicenseRecord): boolean {
  return !!license.expires_at && new Date(license.expires_at).getTime() <= Date.now();
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

async function signObject(env: Env, object: Record<string, unknown>): Promise<{ signedPayload: string; signature: string }> {
  const serialized = JSON.stringify(object);
  const key = await importSigningKey(env);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    encoder.encode(serialized),
  );
  return { signedPayload: b64url(encoder.encode(serialized)), signature: b64url(signature) };
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

async function issueOptimizedLease(
  request: Request,
  env: Env,
  license: LicenseRecord,
  deviceId: string,
): Promise<Response> {
  const configuredHours = Number(env.LEASE_HOURS || 72);
  const leaseHours = Number.isFinite(configuredHours)
    ? Math.max(1, Math.min(configuredHours, 720))
    : 72;
  const now = Date.now();
  const leaseLimit = now + leaseHours * 3600_000;
  const licenseLimit = license.expires_at
    ? new Date(license.expires_at).getTime()
    : Number.POSITIVE_INFINITY;
  const leaseExpiresAt = new Date(Math.min(leaseLimit, licenseLimit)).toISOString();
  const lease: Record<string, unknown> = {
    version: 3,
    licenseId: license.id,
    deviceId,
    edition: license.edition,
    features: ['clean', 'scan', 'optimize'],
    issuedAt: new Date(now).toISOString(),
    serverTime: new Date(now).toISOString(),
    expiresAt: leaseExpiresAt,
    licenseExpiresAt: license.expires_at,
    leaseHours,
    renewalProtocol: 'challenge-refresh',
    nonce: crypto.randomUUID(),
  };
  const signed = await signObject(env, lease);
  await audit(env, request, 'LICENSE_REFRESHED', { leaseHours }, license.id, deviceId);
  return apiJson({
    success: true,
    lease,
    ...signed,
    canonicalBaseUrl: await canonicalBaseUrl(request, env),
  });
}

async function handleChallenge(request: Request, env: Env): Promise<Response> {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (!await consumeRateLimit(env, `challenge:${ip}`, 30, 60)) {
    return apiJson({ success: false, code: 'RATE_LIMITED', message: '请求过于频繁' }, 429);
  }
  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return apiJson({ success: false, code: 'INVALID_JSON', message: '请求格式无效' }, 400);
  }
  const key = String(body.licenseKey || '').trim();
  const deviceId = String(body.deviceId || '').trim();
  if (!key || !deviceId || deviceId.length > 200) {
    return apiJson({ success: false, code: 'INVALID_REQUEST', message: '缺少授权码或设备标识' }, 400);
  }
  const license = await loadLicense(env, key);
  if (!license) return apiJson({ success: false, code: 'LICENSE_NOT_FOUND', message: '授权码不存在' }, 404);
  const device = await env.DB.prepare(`
    SELECT id,license_id,device_id,public_key
    FROM devices
    WHERE license_id=? AND device_id=? AND revoked_at IS NULL
  `).bind(license.id, deviceId).first<ActiveDevice>();
  if (!device?.public_key) {
    return apiJson({ success: false, code: 'DEVICE_NOT_BOUND', message: '设备未绑定或已解绑' }, 403);
  }

  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  const nonce = b64url(nonceBytes);
  const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM device_challenges WHERE license_id=? AND device_id=?')
      .bind(license.id, deviceId),
    env.DB.prepare(`
      INSERT INTO device_challenges(id,license_id,device_id,nonce,expires_at,used_at,created_at)
      VALUES(?,?,?,?,?,NULL,?)
    `).bind(crypto.randomUUID(), license.id, deviceId, nonce, expiresAt, new Date().toISOString()),
  ]);
  return apiJson({
    success: true,
    nonce,
    expiresAt,
    licenseExpiresAt: license.expires_at,
    licenseExpired: isExpired(license),
  });
}

async function handleRefresh(request: Request, env: Env): Promise<Response> {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (!await consumeRateLimit(env, `refresh:${ip}`, 30, 60)) {
    return apiJson({ success: false, code: 'RATE_LIMITED', message: '请求过于频繁' }, 429);
  }
  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return apiJson({ success: false, code: 'INVALID_JSON', message: '请求格式无效' }, 400);
  }
  const key = String(body.licenseKey || '').trim();
  const deviceId = String(body.deviceId || '').trim();
  const nonce = String(body.nonce || '').trim();
  const signature = String(body.signature || '').trim();
  if (!key || !deviceId || !nonce || !signature || deviceId.length > 200 || nonce.length > 256 || signature.length > 1024) {
    return apiJson({ success: false, code: 'INVALID_REQUEST', message: '续期参数无效' }, 400);
  }

  const license = await loadLicense(env, key);
  if (!license) return apiJson({ success: false, code: 'LICENSE_NOT_FOUND', message: '授权码不存在' }, 404);
  const device = await env.DB.prepare(`
    SELECT id,license_id,device_id,public_key
    FROM devices
    WHERE license_id=? AND device_id=? AND revoked_at IS NULL
  `).bind(license.id, deviceId).first<ActiveDevice>();
  if (!device?.public_key) {
    return apiJson({ success: false, code: 'DEVICE_NOT_BOUND', message: '设备未绑定或已解绑，请重新激活' }, 403);
  }

  const challenge = await env.DB.prepare(`
    SELECT id,expires_at
    FROM device_challenges
    WHERE license_id=? AND device_id=? AND nonce=? AND used_at IS NULL
    ORDER BY created_at DESC LIMIT 1
  `).bind(license.id, deviceId, nonce).first<{ id: string; expires_at: string }>();
  if (!challenge || new Date(challenge.expires_at).getTime() <= Date.now()) {
    return apiJson({ success: false, code: 'CHALLENGE_INVALID', message: '设备挑战无效或已过期' }, 403);
  }
  if (!await verifyDeviceSignature(device.public_key, nonce, signature)) {
    return apiJson({ success: false, code: 'INVALID_DEVICE_SIGNATURE', message: '设备签名验证失败' }, 403);
  }
  const used = await env.DB.prepare(`
    UPDATE device_challenges SET used_at=?
    WHERE id=? AND used_at IS NULL AND expires_at>?
  `).bind(new Date().toISOString(), challenge.id, new Date().toISOString()).run();
  if (!used.meta.changes) {
    return apiJson({ success: false, code: 'CHALLENGE_ALREADY_USED', message: '设备挑战已被使用' }, 409);
  }

  if (isExpired(license)) {
    const releasedAt = new Date().toISOString();
    await env.DB.prepare(`
      UPDATE devices SET revoked_at=?,last_seen_at=?
      WHERE id=? AND revoked_at IS NULL
    `).bind(releasedAt, releasedAt, device.id).run();
    await audit(env, request, 'LICENSE_EXPIRED_DEVICE_RELEASED', {
      licenseExpiresAt: license.expires_at,
    }, license.id, deviceId);
    return apiJson({
      success: false,
      code: 'LICENSE_EXPIRED_RELEASED',
      message: '授权已到期，旧设备绑定已释放。现在可以激活新的授权码；如果管理员已为原授权码续期，也可以重新使用原授权码激活。',
      licenseExpiresAt: license.expires_at,
      deviceReleased: true,
      canActivateNewLicense: true,
    }, 403);
  }

  if (license.status.toLowerCase() !== 'active') {
    return apiJson({ success: false, code: 'LICENSE_DISABLED', message: '授权已被管理员禁用' }, 403);
  }

  await env.DB.prepare(`
    UPDATE devices SET last_seen_at=?,app_version=COALESCE(?,app_version),windows_version=COALESCE(?,windows_version)
    WHERE id=?
  `).bind(
    new Date().toISOString(),
    body.appVersion ? String(body.appVersion).slice(0, 100) : null,
    body.windowsVersion ? String(body.windowsVersion).slice(0, 200) : null,
    device.id,
  ).run();
  return issueOptimizedLease(request, env, license, deviceId);
}

async function handleAdminRenew(request: Request, env: Env, licenseId: string): Promise<Response> {
  if (!await validAdminWrite(request, env)) {
    return apiJson({ success: false, code: 'CSRF_OR_AUTH_FAILED', message: '未授权' }, 403);
  }
  let body: Record<string, unknown> = {};
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    // Empty body is allowed; the original duration is used.
  }
  const license = await env.DB.prepare(`
    SELECT id,license_key,license_type,duration_days,expires_at,activated_at,status
    FROM licenses WHERE id=? AND deleted_at IS NULL
  `).bind(licenseId).first<{
    id: string;
    license_key: string;
    license_type: string;
    duration_days: number | null;
    expires_at: string | null;
    activated_at: string | null;
    status: string;
  }>();
  if (!license) return apiJson({ success: false, code: 'LICENSE_NOT_FOUND', message: '授权不存在' }, 404);
  if (license.license_type !== 'duration') {
    return apiJson({ success: false, code: 'RENEW_DURATION_ONLY', message: '只有“激活后 N 天”授权支持按天续期' }, 400);
  }
  if (!license.activated_at || !license.expires_at) {
    return apiJson({ success: false, code: 'LICENSE_NOT_ACTIVATED', message: '该授权尚未首次激活，不需要续期' }, 400);
  }
  const days = Number(body.days ?? license.duration_days ?? 0);
  if (!Number.isInteger(days) || days < 1 || days > 36500) {
    return apiJson({ success: false, code: 'INVALID_RENEW_DAYS', message: '续期天数必须为 1-36500 的整数' }, 400);
  }
  const oldExpiryMs = new Date(license.expires_at).getTime();
  if (!Number.isFinite(oldExpiryMs)) {
    return apiJson({ success: false, code: 'INVALID_LICENSE_EXPIRY', message: '当前授权到期时间异常' }, 500);
  }
  const base = Math.max(Date.now(), oldExpiryMs);
  const newExpiry = new Date(base + days * 86400000).toISOString();
  await env.DB.prepare(`
    UPDATE licenses SET expires_at=?,status='active',updated_at=? WHERE id=?
  `).bind(newExpiry, new Date().toISOString(), license.id).run();
  await audit(env, request, 'LICENSE_RENEWED', {
    days,
    oldExpiresAt: license.expires_at,
    newExpiresAt: newExpiry,
  }, license.id);
  return apiJson({ success: true, expiresAt: newExpiry, days });
}

async function normalizeAdminLicenseCreate(request: Request): Promise<Request> {
  try {
    const body = await request.clone().json() as Record<string, unknown>;
    body.maxDevices = 1;
    const headers = new Headers(request.headers);
    headers.set('content-type', 'application/json');
    return new Request(request.url, {
      method: request.method,
      headers,
      body: JSON.stringify(body),
    });
  } catch {
    return request;
  }
}

async function handleActivation(request: Request, env: Env): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = await request.clone().json() as Record<string, unknown>;
  } catch {
    return worker.fetch(request, env);
  }
  const licenseKey = String(body.licenseKey || '').trim();
  const deviceId = String(body.deviceId || '').trim();
  if (!licenseKey || !deviceId) return worker.fetch(request, env);

  const deviceLockKey = `device:${deviceId}`;
  const licenseLockKey = `license:${licenseKey}`;
  const deviceLock = await acquireLock(env, deviceLockKey);
  if (!deviceLock) {
    return apiJson({ success: false, code: 'ACTIVATION_BUSY', message: '该设备正在执行激活，请稍后重试' }, 409);
  }
  let licenseLock: string | null = null;
  try {
    licenseLock = await acquireLock(env, licenseLockKey);
    if (!licenseLock) {
      return apiJson({ success: false, code: 'ACTIVATION_BUSY', message: '该授权码正在执行激活，其他并发请求已拒绝' }, 409);
    }

    const targetLicense = await loadLicense(env, licenseKey);
    if (targetLicense) {
      const deviceBinding = await env.DB.prepare(`
        SELECT d.id,d.license_id,l.license_key,l.expires_at
        FROM devices d JOIN licenses l ON l.id=d.license_id
        WHERE d.device_id=? AND d.revoked_at IS NULL
        LIMIT 1
      `).bind(deviceId).first<{ id: string; license_id: string; license_key: string; expires_at: string | null }>();
      if (deviceBinding && deviceBinding.license_id !== targetLicense.id) {
        return apiJson({
          success: false,
          code: 'DEVICE_ALREADY_BOUND',
          message: '该设备当前仍绑定其他授权。若旧授权已经到期，请先使用旧授权执行 challenge + refresh 完成到期上报并释放绑定。',
          currentLicenseExpiresAt: deviceBinding.expires_at,
        }, 409);
      }

      const licenseBinding = await env.DB.prepare(`
        SELECT id,device_id FROM devices
        WHERE license_id=? AND revoked_at IS NULL
        LIMIT 1
      `).bind(targetLicense.id).first<{ id: string; device_id: string }>();
      if (licenseBinding && licenseBinding.device_id !== deviceId) {
        return apiJson({
          success: false,
          code: 'LICENSE_ALREADY_BOUND',
          message: '该授权码已经绑定其他设备，必须由管理员解绑后才能换机',
        }, 409);
      }
    }

    return await worker.fetch(request, env);
  } finally {
    if (licenseLock) await releaseLock(env, licenseLockKey, licenseLock);
    await releaseLock(env, deviceLockKey, deviceLock);
  }
}

export async function handlePagesRequest(request: Request, env: Env): Promise<Response> {
  try {
    await ensureSchema(env);
  } catch (error) {
    console.error('D1 schema initialization failed', error);
    if (error instanceof Error && error.message === 'D1_BINDING_MISSING') {
      return apiJson({
        success: false,
        code: 'D1_BINDING_MISSING',
        message: '请在 Cloudflare Pages 项目 Settings > Bindings 中添加 D1 数据库绑定，变量名必须为 DB，然后重新部署。',
      }, 503);
    }
    return apiJson({
      success: false,
      code: 'D1_SCHEMA_INIT_FAILED',
      message: 'D1 数据库自动建表或升级失败，请检查 Pages 的 DB 绑定和数据库状态。',
    }, 500);
  }

  const missing = missingProductionConfig(env);
  if (missing.length) {
    console.error('Missing production configuration:', missing.join(','));
    return apiJson({
      success: false,
      code: 'SERVER_NOT_CONFIGURED',
      message: '授权服务器生产配置不完整，请检查 Cloudflare Pages 的 Variables and Secrets。',
    }, 503);
  }

  const contentLength = Number(request.headers.get('content-length') || 0);
  if (Number.isFinite(contentLength) && contentLength > 64 * 1024) {
    return apiJson({ success: false, code: 'REQUEST_TOO_LARGE', message: '请求体过大' }, 413);
  }

  const path = new URL(request.url).pathname;

  if (path === '/api/v1/device/challenge' && request.method === 'POST') {
    return handleChallenge(request, env);
  }
  if (path === '/api/v1/license/refresh' && request.method === 'POST') {
    return handleRefresh(request, env);
  }
  if (path === '/api/v1/license/validate' && request.method === 'POST') {
    return apiJson({
      success: false,
      code: 'ENDPOINT_DEPRECATED',
      message: '生产客户端不需要每次启动在线验证；请在本地验证签名 Lease，只在 Lease 到期前执行 challenge + refresh。',
    }, 410);
  }
  if (path === '/api/v1/device/verify' && request.method === 'POST') {
    return apiJson({
      success: false,
      code: 'ENDPOINT_DEPRECATED',
      message: '设备签名已合并到 refresh，请使用 challenge + refresh 两步续期。',
    }, 410);
  }

  const renewMatch = path.match(/^\/admin\/api\/licenses\/([^/]+)\/renew$/);
  if (renewMatch && request.method === 'POST') {
    return handleAdminRenew(request, env, renewMatch[1]);
  }

  if (path === '/api/v1/license/activate' && request.method === 'POST') {
    return handleActivation(request, env);
  }

  if (path === '/admin/api/licenses' && request.method === 'POST') {
    request = await normalizeAdminLicenseCreate(request);
  }

  return worker.fetch(request, env);
}
import { normalizePem } from './request-json';
