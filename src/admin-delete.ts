import type { Env } from './worker';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
    .find(value => value.startsWith(name + '='))
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

function decodeId(value: string): string | null {
  try {
    const decoded = decodeURIComponent(value).trim();
    return decoded && decoded.length <= 200 ? decoded : null;
  } catch {
    return null;
  }
}

export async function handleAdminPhysicalDelete(
  request: Request,
  env: Env,
): Promise<Response | null> {
  if (request.method !== 'DELETE') return null;

  const path = new URL(request.url).pathname;
  const deviceMatch = path.match(/^\/admin\/api\/devices\/([^/]+)$/);
  const licenseMatch = path.match(/^\/admin\/api\/licenses\/([^/]+)$/);
  if (!deviceMatch && !licenseMatch) return null;

  if (!await validAdminWrite(request, env)) {
    return json({ success: false, code: 'CSRF_OR_AUTH_FAILED', message: '未授权' }, 403);
  }

  if (deviceMatch) {
    const id = decodeId(deviceMatch[1]);
    if (!id) return json({ success: false, code: 'INVALID_DEVICE_ID', message: '设备记录 ID 无效' }, 400);

    const device = await env.DB.prepare(`
      SELECT id,license_id,device_id,device_name,revoked_at
      FROM devices
      WHERE id=?
    `).bind(id).first<{
      id: string;
      license_id: string;
      device_id: string;
      device_name: string | null;
      revoked_at: string | null;
    }>();

    if (!device) {
      return json({ success: false, code: 'DEVICE_NOT_FOUND', message: '设备记录不存在' }, 404);
    }
    if (!device.revoked_at) {
      return json({
        success: false,
        code: 'DEVICE_STILL_BOUND',
        message: '设备仍处于绑定状态，请先解绑后再删除。',
      }, 409);
    }

    const now = new Date().toISOString();
    const detail = JSON.stringify({
      deletedDeviceRecordId: device.id,
      deviceId: device.device_id,
      deviceName: device.device_name,
      licenseId: device.license_id,
    });

    await env.DB.batch([
      env.DB.prepare(
        'DELETE FROM audit_logs WHERE license_id=? AND device_id=?',
      ).bind(device.license_id, device.device_id),
      env.DB.prepare(
        'DELETE FROM device_challenges WHERE license_id=? AND device_id=?',
      ).bind(device.license_id, device.device_id),
      env.DB.prepare(
        'DELETE FROM rate_limits WHERE bucket_key=?',
      ).bind(`activate-device:${device.device_id}`),
      env.DB.prepare(
        'DELETE FROM devices WHERE id=? AND revoked_at IS NOT NULL',
      ).bind(device.id),
      env.DB.prepare(`
        INSERT INTO audit_logs(id,event_type,ip,license_id,device_id,detail,created_at)
        VALUES(?,?,?,?,?,?,?)
      `).bind(
        crypto.randomUUID(),
        'DEVICE_DELETED',
        request.headers.get('cf-connecting-ip'),
        null,
        null,
        detail,
        now,
      ),
    ]);

    return json({ success: true });
  }

  const id = decodeId(licenseMatch![1]);
  if (!id) return json({ success: false, code: 'INVALID_LICENSE_ID', message: '授权记录 ID 无效' }, 400);

  const license = await env.DB.prepare(`
    SELECT id,license_key,status
    FROM licenses
    WHERE id=? AND deleted_at IS NULL
  `).bind(id).first<{
    id: string;
    license_key: string;
    status: string;
  }>();

  if (!license) {
    return json({ success: false, code: 'LICENSE_NOT_FOUND', message: '授权不存在' }, 404);
  }
  if (license.status !== 'disabled') {
    return json({
      success: false,
      code: 'LICENSE_MUST_BE_DISABLED',
      message: '为防止误删正在使用的客户授权，请先禁用该授权，再执行删除。',
    }, 409);
  }

  const now = new Date().toISOString();
  const detail = JSON.stringify({
    deletedLicenseId: license.id,
    licenseKey: license.license_key,
  });

  await env.DB.batch([
    env.DB.prepare('DELETE FROM audit_logs WHERE license_id=?').bind(license.id),
    env.DB.prepare('DELETE FROM device_challenges WHERE license_id=?').bind(license.id),
    env.DB.prepare('DELETE FROM devices WHERE license_id=?').bind(license.id),
    env.DB.prepare(
      'DELETE FROM activation_locks WHERE license_key=? OR license_key=?',
    ).bind(license.license_key, `license:${license.license_key}`),
    env.DB.prepare(
      'DELETE FROM licenses WHERE id=? AND status=? AND deleted_at IS NULL',
    ).bind(license.id, 'disabled'),
    env.DB.prepare(`
      INSERT INTO audit_logs(id,event_type,ip,license_id,device_id,detail,created_at)
      VALUES(?,?,?,?,?,?,?)
    `).bind(
      crypto.randomUUID(),
      'LICENSE_DELETED',
      request.headers.get('cf-connecting-ip'),
      null,
      null,
      detail,
      now,
    ),
  ]);

  return json({ success: true });
}

