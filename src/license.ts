import type { DeviceRow, Env, JsonObject, LicenseRow, ProofPayload } from './types';
import {
  audit,
  boundedText,
  canonicalBaseUrl,
  decodeB64url,
  decoder,
  encoder,
  fail,
  hmac,
  json,
  normalizePublicKeyPem,
  nowIso,
  optionalText,
  rateLimit,
  readJson,
  safeEqual,
  signObject,
  uuid,
  verifyP256Signature,
  b64url,
} from './common';

const DAY_MS = 86_400_000;

async function loadLicense(env: Env, key: string): Promise<LicenseRow | null> {
  return env.DB.prepare(
    'SELECT id,license_key,edition,status,license_type,duration_days,expires_at,activated_at,max_devices FROM licenses WHERE license_key=? AND deleted_at IS NULL',
  ).bind(key).first<LicenseRow>();
}

function checkLicenseUsable(license: LicenseRow): Response | null {
  if (license.status.toLowerCase() !== 'active') return fail('LICENSE_DISABLED', '授权不可用', 403);
  if (license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) return fail('LICENSE_EXPIRED', '授权已过期', 403);
  if (license.license_type === 'duration' && (!license.duration_days || license.duration_days < 1)) {
    return fail('LICENSE_STATE_INVALID', '授权配置异常', 500);
  }
  return null;
}

function durationExpiryCandidate(license: LicenseRow, activatedAtMs: number): string | null {
  if (license.license_type !== 'duration') return null;
  if (!license.duration_days || license.duration_days < 1) return null;
  return new Date(activatedAtMs + license.duration_days * DAY_MS).toISOString();
}

async function issueDeviceProof(env: Env, licenseId: string, deviceId: string): Promise<string> {
  const payload: ProofPayload = { licenseId, deviceId, exp: Date.now() + 10 * 60_000, nonce: uuid() };
  const encoded = b64url(encoder.encode(JSON.stringify(payload)));
  return `${encoded}.${await hmac(env.DEVICE_PROOF_SECRET, encoded)}`;
}

async function validDeviceProof(env: Env, proof: string, licenseId: string, deviceId: string): Promise<boolean> {
  const [payload, signature] = proof.split('.');
  if (!payload || !signature || proof.length > 4096 || !safeEqual(signature, await hmac(env.DEVICE_PROOF_SECRET, payload))) return false;
  try {
    const parsed = JSON.parse(decoder.decode(decodeB64url(payload))) as ProofPayload;
    return parsed.licenseId === licenseId && parsed.deviceId === deviceId && parsed.exp > Date.now();
  } catch {
    return false;
  }
}

async function issueLease(req: Request, env: Env, license: LicenseRow, deviceId: string): Promise<Response> {
  const configuredHours = Number(env.LEASE_HOURS || 72);
  const hours = Number.isFinite(configuredHours) ? Math.max(1, Math.min(configuredHours, 720)) : 72;
  const leaseLimit = Date.now() + hours * 3_600_000;
  const licenseLimit = license.expires_at ? new Date(license.expires_at).getTime() : Number.POSITIVE_INFINITY;
  if (licenseLimit <= Date.now()) return fail('LICENSE_EXPIRED', '授权已过期', 403);

  const lease: JsonObject = {
    version: 3,
    licenseId: license.id,
    deviceId,
    edition: license.edition,
    features: ['clean', 'scan', 'optimize'],
    issuedAt: nowIso(),
    expiresAt: new Date(Math.min(leaseLimit, licenseLimit)).toISOString(),
    licenseExpiresAt: license.expires_at,
    nonce: uuid(),
  };
  return json({ success: true, lease, ...await signObject(env, lease), canonicalBaseUrl: await canonicalBaseUrl(req, env) });
}

async function getDevice(env: Env, licenseId: string, deviceId: string): Promise<DeviceRow | null> {
  return env.DB.prepare(
    'SELECT id,license_id,device_id,public_key,device_name,windows_version,app_version,first_seen_at,last_seen_at,revoked_at FROM devices WHERE license_id=? AND device_id=?',
  ).bind(licenseId, deviceId).first<DeviceRow>();
}

async function updateFirstActivationIfNeeded(env: Env, license: LicenseRow, deviceId: string, timeIso: string, timeMs: number): Promise<void> {
  const candidate = durationExpiryCandidate(license, timeMs);
  await env.DB.prepare(`UPDATE licenses SET
      activated_at=COALESCE(activated_at,?),
      expires_at=CASE WHEN license_type='duration' AND activated_at IS NULL THEN ? ELSE expires_at END,
      updated_at=CASE WHEN activated_at IS NULL THEN ? ELSE updated_at END
    WHERE id=? AND EXISTS(
      SELECT 1 FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL
    )`)
    .bind(timeIso, candidate, timeIso, license.id, license.id, deviceId)
    .run();
}

async function bindNewOrRevokedDevice(
  env: Env,
  license: LicenseRow,
  existing: DeviceRow | null,
  deviceId: string,
  publicKey: string,
  deviceName: string | null,
  windowsVersion: string | null,
  appVersion: string | null,
  timeIso: string,
  timeMs: number,
): Promise<'bound' | 'rebound' | 'race' | 'limit'> {
  const expiryCheck = timeIso;
  const candidate = durationExpiryCandidate(license, timeMs);
  let results;

  if (existing) {
    results = await env.DB.batch([
      env.DB.prepare(`UPDATE devices SET
          public_key=?,device_name=COALESCE(?,device_name),windows_version=COALESCE(?,windows_version),
          app_version=COALESCE(?,app_version),last_seen_at=?,revoked_at=NULL
        WHERE id=? AND revoked_at IS NOT NULL
          AND (SELECT COUNT(*) FROM devices WHERE license_id=? AND revoked_at IS NULL)
              < (SELECT max_devices FROM licenses WHERE id=? AND status='active' AND (expires_at IS NULL OR expires_at>?))`)
        .bind(publicKey, deviceName, windowsVersion, appVersion, timeIso, existing.id, license.id, license.id, expiryCheck),
      env.DB.prepare(`UPDATE licenses SET
          activated_at=COALESCE(activated_at,?),
          expires_at=CASE WHEN license_type='duration' AND activated_at IS NULL THEN ? ELSE expires_at END,
          updated_at=CASE WHEN activated_at IS NULL THEN ? ELSE updated_at END
        WHERE id=? AND EXISTS(
          SELECT 1 FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL
        )`)
        .bind(timeIso, candidate, timeIso, license.id, license.id, deviceId),
    ]);
    if ((results[0].meta.changes || 0) > 0) return 'rebound';
  } else {
    results = await env.DB.batch([
      env.DB.prepare(`INSERT OR IGNORE INTO devices(
          id,license_id,device_id,public_key,device_name,windows_version,app_version,first_seen_at,last_seen_at
        ) SELECT ?,?,?,?,?,?,?,?,?
        WHERE (SELECT COUNT(*) FROM devices WHERE license_id=? AND revoked_at IS NULL)
              < (SELECT max_devices FROM licenses WHERE id=? AND status='active' AND (expires_at IS NULL OR expires_at>?))`)
        .bind(uuid(), license.id, deviceId, publicKey, deviceName, windowsVersion, appVersion, timeIso, timeIso, license.id, license.id, expiryCheck),
      env.DB.prepare(`UPDATE licenses SET
          activated_at=COALESCE(activated_at,?),
          expires_at=CASE WHEN license_type='duration' AND activated_at IS NULL THEN ? ELSE expires_at END,
          updated_at=CASE WHEN activated_at IS NULL THEN ? ELSE updated_at END
        WHERE id=? AND EXISTS(
          SELECT 1 FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL
        )`)
        .bind(timeIso, candidate, timeIso, license.id, license.id, deviceId),
    ]);
    if ((results[0].meta.changes || 0) > 0) return 'bound';
  }

  const raced = await getDevice(env, license.id, deviceId);
  if (raced && !raced.revoked_at) return 'race';
  return 'limit';
}

export async function activate(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(env, `activate:${ip}`, 10, 60)) return fail('RATE_LIMITED', '请求过于频繁', 429);

  const body = await readJson(req);
  const key = boundedText(body.licenseKey, 80);
  const deviceId = boundedText(body.deviceId, 200);
  const submittedPublicKey = boundedText(body.devicePublicKey, 4000, false);
  if (!key || !deviceId || !submittedPublicKey) return fail('INVALID_REQUEST', '缺少或无效的授权码、设备标识或设备公钥');
  const publicKey = await normalizePublicKeyPem(submittedPublicKey);
  if (!publicKey) return fail('INVALID_DEVICE_KEY', '设备公钥必须是有效的 P-256 SPKI PEM 公钥');

  let license = await loadLicense(env, key);
  if (!license) {
    await audit(env, req, 'LICENSE_REJECTED', { code: 'LICENSE_NOT_FOUND' });
    return fail('LICENSE_NOT_FOUND', '授权码不存在', 404);
  }
  const unusable = checkLicenseUsable(license);
  if (unusable) return unusable;

  const deviceName = optionalText(body.deviceName, 120);
  const windowsVersion = optionalText(body.windowsVersion, 120);
  const appVersion = optionalText(body.appVersion, 80);
  const timeMs = Date.now();
  const timeIso = new Date(timeMs).toISOString();
  let existing = await getDevice(env, license.id, deviceId);

  if (existing && !existing.revoked_at) {
    if (!existing.public_key) return fail('DEVICE_KEY_MISSING', '已绑定设备缺少公钥，请管理员解绑后重新激活', 409);
    const canonicalExistingKey = await normalizePublicKeyPem(existing.public_key);
    if (!canonicalExistingKey || canonicalExistingKey !== publicKey) return fail('DEVICE_KEY_MISMATCH', '设备公钥与已绑定设备不一致', 403);
    await env.DB.batch([
      env.DB.prepare('UPDATE devices SET public_key=?,last_seen_at=?,device_name=COALESCE(?,device_name),windows_version=COALESCE(?,windows_version),app_version=COALESCE(?,app_version) WHERE id=?')
        .bind(publicKey, timeIso, deviceName, windowsVersion, appVersion, existing.id),
      env.DB.prepare(`UPDATE licenses SET
          activated_at=COALESCE(activated_at,?),
          expires_at=CASE WHEN license_type='duration' AND activated_at IS NULL THEN ? ELSE expires_at END,
          updated_at=CASE WHEN activated_at IS NULL THEN ? ELSE updated_at END
        WHERE id=?`)
        .bind(timeIso, durationExpiryCandidate(license, timeMs), timeIso, license.id),
    ]);
  } else {
    const outcome = await bindNewOrRevokedDevice(env, license, existing, deviceId, publicKey, deviceName, windowsVersion, appVersion, timeIso, timeMs);
    if (outcome === 'limit') {
      const latestLicense = await loadLicense(env, key);
      if (!latestLicense) return fail('LICENSE_NOT_FOUND', '授权码不存在', 404);
      const latestUnusable = checkLicenseUsable(latestLicense);
      if (latestUnusable) return latestUnusable;
      return fail('DEVICE_LIMIT_REACHED', '已达到设备数量限制', 409);
    }
    existing = await getDevice(env, license.id, deviceId);
    if (!existing || existing.revoked_at) return fail('DEVICE_BIND_FAILED', '设备绑定失败，请重试', 409);
    const canonicalExistingKey = existing.public_key ? await normalizePublicKeyPem(existing.public_key) : null;
    if (!canonicalExistingKey || canonicalExistingKey !== publicKey) return fail('DEVICE_KEY_MISMATCH', '并发激活时检测到设备公钥不一致', 409);
    if (outcome === 'bound') await audit(env, req, 'DEVICE_BOUND', { deviceName }, license.id, deviceId);
    if (outcome === 'rebound') await audit(env, req, 'DEVICE_REBOUND', { deviceName }, license.id, deviceId);
  }

  license = await loadLicense(env, key);
  if (!license) return fail('LICENSE_NOT_FOUND', '授权码不存在', 404);
  const finalUnusable = checkLicenseUsable(license);
  if (finalUnusable) return finalUnusable;
  if (license.license_type === 'duration' && (!license.activated_at || !license.expires_at)) {
    return fail('LICENSE_STATE_INVALID', '时长授权首次激活状态写入失败', 500);
  }
  return issueLease(req, env, license, deviceId);
}

export async function validateOrRefresh(req: Request, env: Env, mode: 'validate' | 'refresh'): Promise<Response> {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(env, `${mode}:${ip}`, 60, 60)) return fail('RATE_LIMITED', '请求过于频繁', 429);
  const body = await readJson(req);
  const key = boundedText(body.licenseKey, 80);
  const deviceId = boundedText(body.deviceId, 200);
  const proof = boundedText(body.deviceProof, 4096, false);
  if (!key || !deviceId || !proof) return fail('INVALID_REQUEST', '缺少授权码、设备标识或设备证明');

  const license = await loadLicense(env, key);
  if (!license) return fail('LICENSE_NOT_FOUND', '授权码不存在', 404);
  const unusable = checkLicenseUsable(license);
  if (unusable) return unusable;
  const device = await env.DB.prepare('SELECT id FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL')
    .bind(license.id, deviceId).first<{ id: string }>();
  if (!device) return fail('DEVICE_NOT_BOUND', '设备未绑定或已解绑，请重新激活', 403);
  if (!await validDeviceProof(env, proof, license.id, deviceId)) return fail('DEVICE_PROOF_REQUIRED', '设备证明无效或已过期，请重新执行 challenge/verify', 403);

  await env.DB.prepare('UPDATE devices SET last_seen_at=?,app_version=COALESCE(?,app_version),windows_version=COALESCE(?,windows_version) WHERE id=?')
    .bind(nowIso(), optionalText(body.appVersion, 80), optionalText(body.windowsVersion, 120), device.id)
    .run();
  return issueLease(req, env, license, deviceId);
}

export async function challenge(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(env, `challenge:${ip}`, 30, 60)) return fail('RATE_LIMITED', '设备验证请求过于频繁', 429);
  const body = await readJson(req);
  const key = boundedText(body.licenseKey, 80);
  const deviceId = boundedText(body.deviceId, 200);
  if (!key || !deviceId) return fail('INVALID_REQUEST', '缺少授权码或设备标识');

  const license = await loadLicense(env, key);
  if (!license) return fail('LICENSE_NOT_FOUND', '授权码不存在', 404);
  const unusable = checkLicenseUsable(license);
  if (unusable) return unusable;
  const active = await env.DB.prepare('SELECT id,public_key FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL')
    .bind(license.id, deviceId).first<{ id: string; public_key: string | null }>();
  if (!active?.public_key) return fail('DEVICE_NOT_BOUND', '设备未绑定或没有设备公钥', 404);

  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const nonce = b64url(bytes);
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM device_challenges WHERE license_id=? AND device_id=? AND (expires_at<? OR used_at IS NOT NULL)')
      .bind(license.id, deviceId, createdAt),
    env.DB.prepare('INSERT INTO device_challenges(id,license_id,device_id,nonce,expires_at,used_at,created_at) VALUES(?,?,?,?,?,NULL,?)')
      .bind(uuid(), license.id, deviceId, nonce, expiresAt, createdAt),
  ]);
  return json({ success: true, nonce, expiresAt });
}

export async function verifyDevice(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(env, `verify:${ip}`, 60, 60)) return fail('RATE_LIMITED', '设备签名验证请求过于频繁', 429);
  const body = await readJson(req);
  const key = boundedText(body.licenseKey, 80);
  const deviceId = boundedText(body.deviceId, 200);
  const nonce = boundedText(body.nonce, 512, false);
  const signature = boundedText(body.signature, 1024, false);
  if (!key || !deviceId || !nonce || !signature) return fail('INVALID_REQUEST', '缺少设备验证参数');

  const license = await loadLicense(env, key);
  if (!license) return fail('LICENSE_NOT_FOUND', '授权码不存在', 404);
  const unusable = checkLicenseUsable(license);
  if (unusable) return unusable;
  const device = await env.DB.prepare('SELECT public_key FROM devices WHERE license_id=? AND device_id=? AND revoked_at IS NULL')
    .bind(license.id, deviceId).first<{ public_key: string | null }>();
  const challengeRow = await env.DB.prepare('SELECT id,expires_at FROM device_challenges WHERE license_id=? AND device_id=? AND nonce=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1')
    .bind(license.id, deviceId, nonce).first<{ id: string; expires_at: string }>();
  if (!device?.public_key || !challengeRow || new Date(challengeRow.expires_at).getTime() <= Date.now()) {
    return fail('INVALID_DEVICE_SIGNATURE', '设备验证失败', 403);
  }
  if (!await verifyP256Signature(device.public_key, signature, nonce)) return fail('INVALID_DEVICE_SIGNATURE', '设备签名验证失败', 403);

  const used = await env.DB.prepare('UPDATE device_challenges SET used_at=? WHERE id=? AND used_at IS NULL')
    .bind(nowIso(), challengeRow.id).run();
  if (!used.meta.changes) return fail('CHALLENGE_ALREADY_USED', '设备挑战已被使用', 409);
  await audit(env, req, 'DEVICE_VERIFIED', null, license.id, deviceId);
  return json({ success: true, verified: true, deviceProof: await issueDeviceProof(env, license.id, deviceId), proofExpiresInSeconds: 600 });
}
