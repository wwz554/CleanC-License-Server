import worker, { type Env } from './worker';

let schemaReady: Promise<void> | null = null;

const REQUIRED_SECRETS: Array<keyof Env> = [
  'ADMIN_PASSWORD',
  'SESSION_SECRET',
  'DEVICE_PROOF_SECRET',
  'TURNSTILE_SECRET',
  'LICENSE_SIGNING_PRIVATE_KEY',
];

function missingProductionConfig(env: Env): string[] {
  const missing: string[] = [];
  for (const key of REQUIRED_SECRETS) {
    const value = String(env[key] || '').trim();
    if (!value) missing.push(String(key));
  }
  if (!String(env.TURNSTILE_SITE_KEY || '').trim()) missing.push('TURNSTILE_SITE_KEY');
  return missing;
}

async function ensureSchema(env: Env): Promise<void> {
  if (!env.DB) throw new Error('D1_BINDING_MISSING');
  if (schemaReady) return schemaReady;

  schemaReady = (async () => {
    const statements = [
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
      `CREATE TABLE IF NOT EXISTS system_settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT,
        updated_at TEXT NOT NULL
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
      `CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)`,
      `CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_id)`,
      `CREATE INDEX IF NOT EXISTS idx_devices_license_active ON devices(license_id, revoked_at)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_challenges_device ON device_challenges(device_id, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_challenges_expiry ON device_challenges(expires_at, used_at)`,
      `CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start)`,
      `CREATE INDEX IF NOT EXISTS idx_activation_locks_until ON activation_locks(locked_until)`
    ];

    for (const sql of statements) await env.DB.prepare(sql).run();

    const columns = await env.DB.prepare('PRAGMA table_info(device_challenges)').all<{ name: string }>();
    const hasLicenseId = columns.results.some(column => column.name === 'license_id');
    if (!hasLicenseId) {
      try {
        await env.DB.prepare('ALTER TABLE device_challenges ADD COLUMN license_id TEXT').run();
      } catch (error) {
        // Another isolate may have upgraded the table between PRAGMA and ALTER.
        const after = await env.DB.prepare('PRAGMA table_info(device_challenges)').all<{ name: string }>();
        if (!after.results.some(column => column.name === 'license_id')) throw error;
      }
    }
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_challenges_license_device ON device_challenges(license_id, device_id, created_at DESC)').run();

    const nowSeconds = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(nowSeconds - 7 * 86400),
      env.DB.prepare('DELETE FROM device_challenges WHERE expires_at < ? OR used_at IS NOT NULL').bind(new Date(Date.now() - 86400000).toISOString()),
      env.DB.prepare('DELETE FROM activation_locks WHERE locked_until < ?').bind(Date.now() - 60000),
    ]);
  })().catch(error => {
    schemaReady = null;
    throw error;
  });

  return schemaReady;
}

async function acquireActivationLock(env: Env, licenseKey: string): Promise<string | null> {
  const token = crypto.randomUUID();
  const now = Date.now();
  const until = now + 15000;
  const row = await env.DB.prepare(`
    INSERT INTO activation_locks(license_key, lock_token, locked_until)
    VALUES(?,?,?)
    ON CONFLICT(license_key) DO UPDATE SET
      lock_token=excluded.lock_token,
      locked_until=excluded.locked_until
    WHERE activation_locks.locked_until < ?
    RETURNING lock_token
  `).bind(licenseKey, token, until, now).first<{ lock_token: string }>();
  return row?.lock_token === token ? token : null;
}

async function releaseActivationLock(env: Env, licenseKey: string, token: string): Promise<void> {
  try {
    await env.DB.prepare('DELETE FROM activation_locks WHERE license_key=? AND lock_token=?').bind(licenseKey, token).run();
  } catch (error) {
    console.error('Failed to release activation lock', error);
  }
}

async function validateAdminLicenseRequest(request: Request): Promise<Response | null> {
  if (request.method !== 'POST' || new URL(request.url).pathname !== '/admin/api/licenses') return null;
  try {
    const body = await request.clone().json() as Record<string, unknown>;
    const type = String(body.licenseType || '');
    if (!['permanent', 'duration', 'fixed'].includes(type)) {
      return Response.json({ success: false, code: 'INVALID_LICENSE_TYPE', message: '授权类型无效' }, { status: 400 });
    }
  } catch {
    // The worker will return the canonical JSON/content-type error.
  }
  return null;
}

export async function handlePagesRequest(request: Request, env: Env): Promise<Response> {
  try {
    await ensureSchema(env);
  } catch (error) {
    console.error('D1 schema initialization failed', error);
    if (error instanceof Error && error.message === 'D1_BINDING_MISSING') {
      return Response.json({
        success: false,
        code: 'D1_BINDING_MISSING',
        message: '请在 Cloudflare Pages 项目 Settings > Bindings 中添加 D1 数据库绑定，变量名必须为 DB，然后重新部署。'
      }, { status: 503 });
    }
    return Response.json({
      success: false,
      code: 'D1_SCHEMA_INIT_FAILED',
      message: 'D1 数据库自动建表失败，请检查 Pages 的 DB 绑定和数据库权限。'
    }, { status: 500 });
  }

  const missing = missingProductionConfig(env);
  if (missing.length) {
    console.error('Missing production configuration:', missing.join(','));
    return Response.json({
      success: false,
      code: 'SERVER_NOT_CONFIGURED',
      message: '授权服务器生产配置不完整，请检查 Cloudflare Pages 的 Variables and Secrets。'
    }, { status: 503 });
  }

  const contentLength = Number(request.headers.get('content-length') || 0);
  if (Number.isFinite(contentLength) && contentLength > 64 * 1024) {
    return Response.json({ success: false, code: 'REQUEST_TOO_LARGE', message: '请求体过大' }, { status: 413 });
  }

  const adminValidation = await validateAdminLicenseRequest(request);
  if (adminValidation) return adminValidation;

  const path = new URL(request.url).pathname;
  if (path === '/api/v1/license/activate' && request.method === 'POST') {
    let licenseKey = '';
    try {
      const body = await request.clone().json() as Record<string, unknown>;
      licenseKey = String(body.licenseKey || '').trim();
    } catch {
      return worker.fetch(request, env);
    }
    if (!licenseKey) return worker.fetch(request, env);

    const lockToken = await acquireActivationLock(env, licenseKey);
    if (!lockToken) {
      return Response.json({
        success: false,
        code: 'ACTIVATION_BUSY',
        message: '该授权码正在执行激活，请稍后重试。'
      }, { status: 409 });
    }
    try {
      return await worker.fetch(request, env);
    } finally {
      await releaseActivationLock(env, licenseKey, lockToken);
    }
  }

  return worker.fetch(request, env);
}
