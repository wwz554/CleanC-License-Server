import worker, { type Env } from './worker';

let schemaReady: Promise<void> | null = null;

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
      `CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)`,
      `CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_id)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_challenges_device ON device_challenges(device_id, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_challenges_license_device ON device_challenges(license_id, device_id, created_at DESC)`
    ];

    for (const sql of statements) await env.DB.prepare(sql).run();

    const columns = await env.DB.prepare('PRAGMA table_info(device_challenges)').all<{ name: string }>();
    const hasLicenseId = columns.results.some(column => column.name === 'license_id');
    if (!hasLicenseId) {
      await env.DB.prepare('ALTER TABLE device_challenges ADD COLUMN license_id TEXT').run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_challenges_license_device ON device_challenges(license_id, device_id, created_at DESC)').run();
    }
  })().catch(error => {
    schemaReady = null;
    throw error;
  });

  return schemaReady;
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

  return worker.fetch(request, env);
}
