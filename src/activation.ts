import type { Env } from './worker';

const API_VERSION = 3;
const LEASE_VERSION = 4;
const encoder = new TextEncoder();
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

type DeviceRecord = {
  id: string;
  license_id: string;
  device_id: string;
  public_key: string | null;
  device_name: string | null;
  windows_version: string | null;
  app_version: string | null;
  revoked_at: string | null;
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

async function acquireLock(env: Env, lockKey: string): Promise<string | null> {
  const token = crypto.randomUUID();
  const now = Date.now();
  const until = now + 30_000;
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
    await env.DB.prepare('DELETE FROM activation_locks WHERE license_key=? AND lock_token=?')
      .bind(lockKey, token).run();
  } catch (error) {
    console.error('Failed to release activation lock', error);
  }
}

async function loadLicense(env: Env, licenseKey: string): Promise<LicenseRecord | null> {
  return env.DB.prepare(`
    SELECT id,license_key,edition,status,license_type,duration_days,expires_at,activated_at
    FROM licenses
    WHERE license_key=? AND deleted_at IS NULL
  `).bind(licenseKey).first<LicenseRecord>();
}

async function getSetting(env: Env, key: string): Promise<string | null> {
  return (await env.DB.prepare('SELECT setting_value FROM system_settings WHERE setting_key=?')
    .bind(key).first<{ setting_value: string }>())?.setting_value || null;
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
  return { signedPayload: b64url(encoder.encode(serialized)), signature: b64url(signature) };
}

async function normalizePublicKey(pem: string): Promise<string | null> {
  try {
    const raw = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
    if (!raw) return null;
    const der = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
    await crypto.subtle.importKey(
      'spki',
      der,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return b64url(der);
  } catch {
    return null;
  }
}

async function auditSafe(
  env: Env,
  request: Request,
  eventType: string,
  detail: unknown,
  licenseId: string | null,
  deviceId: string | null,
): Promise<void> {
  try {
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
  } catch (error) {
    console.error('Audit log write failed', error);
  }
}

async function issueLease(request: Request, env: Env, license: LicenseRecord, deviceId: string): Promise<Response> {
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
  return json({
    success: true,
    lease,
    ...await signObject(env, lease),
    canonicalBaseUrl: await canonicalBaseUrl(request, env),
  });
}

function expired(license: LicenseRecord): boolean {
  return !!license.expires_at && new Date(license.expires_at).getTime() <= Date.now();
}

export async function handleProductionActivation(request: Request, env: Env): Promise<Response> {
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (Number.isFinite(contentLength) && contentLength > 64 * 1024) {
    return json({ success: false, code: 'REQUEST_TOO_LARGE', message: '请求体过大' }, 413);
  }
  if (!(request.headers.get('content-type') || '').toLowerCase().includes('application/json')) {
    return json({ success: false, code: 'INVALID_CONTENT_TYPE', message: '请求必须使用 application/json' }, 415);
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return json({ success: false, code: 'INVALID_JSON', message: '请求 JSON 格式无效' }, 400);
  }

  const licenseKey = String(body.licenseKey || '').trim();
  const deviceId = String(body.deviceId || '').trim();
  const publicKeyPem = String(body.devicePublicKey || '').trim();
  if (!licenseKey || licenseKey.length > 200 || !deviceId || deviceId.length > 200 || !publicKeyPem || publicKeyPem.length > 4000) {
    return json({ success: false, code: 'INVALID_REQUEST', message: '授权码、设备标识或设备公钥无效' }, 400);
  }

  const normalizedNewKey = await normalizePublicKey(publicKeyPem);
  if (!normalizedNewKey) {
    return json({ success: false, code: 'INVALID_DEVICE_PUBLIC_KEY', message: '设备公钥必须是 P-256 SPKI PEM 格式' }, 400);
  }

  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  // 宽松公网 IP 总限流，避免公司/校园/运营商 NAT 下几十台正常设备互相误伤。
  if (!await consumeRateLimit(env, `activate-ip:${ip}`, 300, 60)) {
    return json({ success: false, code: 'RATE_LIMITED', message: '该网络激活请求过多，请稍后重试' }, 429);
  }
  // 同一设备仍有细粒度限流，防止单机暴力重复请求。
  if (!await consumeRateLimit(env, `activate-device:${deviceId}`, 10, 60)) {
    return json({ success: false, code: 'RATE_LIMITED', message: '该设备激活请求过于频繁，请稍后重试' }, 429);
  }

  const deviceLockKey = `device:${deviceId}`;
  const licenseLockKey = `license:${licenseKey}`;
  const deviceLock = await acquireLock(env, deviceLockKey);
  if (!deviceLock) {
    return json({ success: false, code: 'ACTIVATION_BUSY', message: '该设备正在执行激活，请稍后重试' }, 409);
  }

  let licenseLock: string | null = null;
  try {
    licenseLock = await acquireLock(env, licenseLockKey);
    if (!licenseLock) {
      return json({ success: false, code: 'ACTIVATION_BUSY', message: '该授权码正在执行激活，其他并发请求已拒绝' }, 409);
    }

    let license = await loadLicense(env, licenseKey);
    if (!license) {
      await auditSafe(env, request, 'LICENSE_REJECTED', { code: 'LICENSE_NOT_FOUND' }, null, deviceId);
      return json({ success: false, code: 'LICENSE_NOT_FOUND', message: '授权码不存在' }, 404);
    }
    if (license.status.toLowerCase() !== 'active') {
      return json({ success: false, code: 'LICENSE_DISABLED', message: '授权已被管理员禁用' }, 403);
    }
    if (expired(license)) {
      return json({ success: false, code: 'LICENSE_EXPIRED', message: '授权已过期' }, 403);
    }

    const deviceBinding = await env.DB.prepare(`
      SELECT d.id,d.license_id,l.license_key,l.expires_at
      FROM devices d JOIN licenses l ON l.id=d.license_id
      WHERE d.device_id=? AND d.revoked_at IS NULL
      LIMIT 1
    `).bind(deviceId).first<{ id: string; license_id: string; license_key: string; expires_at: string | null }>();
    if (deviceBinding && deviceBinding.license_id !== license.id) {
      return json({
        success: false,
        code: 'DEVICE_ALREADY_BOUND',
        message: '该设备当前仍绑定其他授权。旧授权到期后请先完成 challenge + refresh 释放，或由管理员手动解绑。',
        currentLicenseExpiresAt: deviceBinding.expires_at,
      }, 409);
    }

    const licenseBinding = await env.DB.prepare(`
      SELECT id,device_id FROM devices
      WHERE license_id=? AND revoked_at IS NULL
      LIMIT 1
    `).bind(license.id).first<{ id: string; device_id: string }>();
    if (licenseBinding && licenseBinding.device_id !== deviceId) {
      return json({
        success: false,
        code: 'LICENSE_ALREADY_BOUND',
        message: '该授权码已经绑定其他设备，必须由管理员解绑后才能换机',
      }, 409);
    }

    const existing = await env.DB.prepare(`
      SELECT id,license_id,device_id,public_key,device_name,windows_version,app_version,revoked_at
      FROM devices WHERE license_id=? AND device_id=?
    `).bind(license.id, deviceId).first<DeviceRecord>();

    const time = new Date().toISOString();
    const deviceName = body.deviceName ? String(body.deviceName).slice(0, 200) : null;
    const windowsVersion = body.windowsVersion ? String(body.windowsVersion).slice(0, 200) : null;
    const appVersion = body.appVersion ? String(body.appVersion).slice(0, 100) : null;

    if (existing && !existing.revoked_at) {
      if (!existing.public_key) {
        return json({ success: false, code: 'DEVICE_KEY_MISSING', message: '已绑定设备缺少公钥，请管理员先解绑后重新激活' }, 409);
      }
      const normalizedExistingKey = await normalizePublicKey(existing.public_key);
      if (!normalizedExistingKey || normalizedExistingKey !== normalizedNewKey) {
        return json({ success: false, code: 'DEVICE_KEY_MISMATCH', message: '设备公钥与已绑定设备不一致' }, 403);
      }
      await env.DB.prepare(`
        UPDATE devices SET last_seen_at=?,device_name=COALESCE(?,device_name),
          windows_version=COALESCE(?,windows_version),app_version=COALESCE(?,app_version)
        WHERE id=? AND revoked_at IS NULL
      `).bind(time, deviceName, windowsVersion, appVersion, existing.id).run();
      license = await loadLicense(env, licenseKey) || license;
      return issueLease(request, env, license, deviceId);
    }

    let firstExpiry: string | null = null;
    if (!license.activated_at && license.license_type === 'duration') {
      if (!license.duration_days || license.duration_days < 1 || license.duration_days > 36500) {
        return json({ success: false, code: 'INVALID_DURATION', message: '授权有效天数异常，请联系管理员' }, 500);
      }
      firstExpiry = new Date(Date.now() + license.duration_days * 86400000).toISOString();
    }

    const statements: D1PreparedStatement[] = [];
    if (existing) {
      statements.push(env.DB.prepare(`
        UPDATE devices SET public_key=?,device_name=?,windows_version=?,app_version=?,
          last_seen_at=?,revoked_at=NULL
        WHERE id=?
      `).bind(publicKeyPem, deviceName || existing.device_name, windowsVersion || existing.windows_version,
        appVersion || existing.app_version, time, existing.id));
    } else {
      statements.push(env.DB.prepare(`
        INSERT INTO devices(id,license_id,device_id,public_key,device_name,windows_version,app_version,first_seen_at,last_seen_at,revoked_at)
        VALUES(?,?,?,?,?,?,?,?,?,NULL)
      `).bind(crypto.randomUUID(), license.id, deviceId, publicKeyPem, deviceName, windowsVersion, appVersion, time, time));
    }

    if (!license.activated_at && license.license_type === 'duration') {
      statements.push(env.DB.prepare(`
        UPDATE licenses SET activated_at=?,expires_at=?,updated_at=?
        WHERE id=? AND activated_at IS NULL
      `).bind(time, firstExpiry, time, license.id));
    } else {
      statements.push(env.DB.prepare(`
        UPDATE licenses SET activated_at=COALESCE(activated_at,?),updated_at=? WHERE id=?
      `).bind(time, time, license.id));
    }

    try {
      await env.DB.batch(statements);
    } catch (error) {
      console.error('Activation database write failed', error);
      const currentLicenseBinding = await env.DB.prepare(`
        SELECT device_id FROM devices WHERE license_id=? AND revoked_at IS NULL LIMIT 1
      `).bind(license.id).first<{ device_id: string }>();
      if (currentLicenseBinding && currentLicenseBinding.device_id !== deviceId) {
        return json({ success: false, code: 'LICENSE_ALREADY_BOUND', message: '该授权码已经被其他设备抢先绑定' }, 409);
      }
      const currentDeviceBinding = await env.DB.prepare(`
        SELECT license_id FROM devices WHERE device_id=? AND revoked_at IS NULL LIMIT 1
      `).bind(deviceId).first<{ license_id: string }>();
      if (currentDeviceBinding && currentDeviceBinding.license_id !== license.id) {
        return json({ success: false, code: 'DEVICE_ALREADY_BOUND', message: '该设备已经被其他授权抢先绑定' }, 409);
      }
      return json({ success: false, code: 'ACTIVATION_CONFLICT', message: '激活发生并发冲突，请重试' }, 409);
    }

    license = await loadLicense(env, licenseKey) || license;
    await auditSafe(env, request, existing ? 'DEVICE_REBOUND' : 'DEVICE_BOUND', null, license.id, deviceId);
    return issueLease(request, env, license, deviceId);
  } finally {
    if (licenseLock) await releaseLock(env, licenseLockKey, licenseLock);
    await releaseLock(env, deviceLockKey, deviceLock);
  }
}
