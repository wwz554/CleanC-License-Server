import server from './server';
import type { Env } from './types';

const SCHEMA_VERSION = '3';
const CLEANUP_INTERVAL_MS = 24 * 3_600_000;
let schemaReady: Promise<void> | null = null;

async function ensureSchema(env: Env): Promise<void> {
  if (!env.DB) throw new Error('D1_BINDING_MISSING');
  if (schemaReady) return schemaReady;

  schemaReady = (async () => {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS schema_meta (
      meta_key TEXT PRIMARY KEY,
      meta_value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`).run();

    const metaRows = await env.DB.prepare("SELECT meta_key,meta_value FROM schema_meta WHERE meta_key IN ('schema_version','last_cleanup_at')")
      .all<{ meta_key: string; meta_value: string }>();
    const meta = new Map(metaRows.results.map(row => [row.meta_key, row.meta_value]));

    if (meta.get('schema_version') !== SCHEMA_VERSION) {
      await env.DB.batch([
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS licenses (
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
        )`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS devices (
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
        )`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS audit_logs (
          id TEXT PRIMARY KEY,
          event_type TEXT NOT NULL,
          ip TEXT,
          license_id TEXT,
          device_id TEXT,
          detail TEXT,
          created_at TEXT NOT NULL
        )`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS system_settings (
          setting_key TEXT PRIMARY KEY,
          setting_value TEXT,
          updated_at TEXT NOT NULL
        )`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS domain_history (
          id TEXT PRIMARY KEY,
          old_url TEXT,
          new_url TEXT NOT NULL,
          ip TEXT,
          created_at TEXT NOT NULL
        )`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS device_challenges (
          id TEXT PRIMARY KEY,
          license_id TEXT,
          device_id TEXT NOT NULL,
          nonce TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          used_at TEXT,
          created_at TEXT NOT NULL
        )`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS rate_limits (
          bucket_key TEXT PRIMARY KEY,
          count INTEGER NOT NULL,
          window_start INTEGER NOT NULL
        )`),
        env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)'),
        env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_id)'),
        env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC)'),
        env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_challenges_device ON device_challenges(device_id, created_at DESC)'),
        env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_challenges_expiry ON device_challenges(expires_at)'),
        env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_rate_window ON rate_limits(window_start)'),
      ]);

      const columns = await env.DB.prepare('PRAGMA table_info(device_challenges)').all<{ name: string }>();
      if (!columns.results.some(column => column.name === 'license_id')) {
        await env.DB.prepare('ALTER TABLE device_challenges ADD COLUMN license_id TEXT').run();
      }
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_challenges_license_device ON device_challenges(license_id, device_id, created_at DESC)').run();
      await env.DB.prepare(`INSERT INTO schema_meta(meta_key,meta_value,updated_at) VALUES('schema_version',?,?)
        ON CONFLICT(meta_key) DO UPDATE SET meta_value=excluded.meta_value,updated_at=excluded.updated_at`)
        .bind(SCHEMA_VERSION, new Date().toISOString()).run();
    }

    const now = Date.now();
    const lastCleanup = Date.parse(meta.get('last_cleanup_at') || '');
    if (!Number.isFinite(lastCleanup) || now - lastCleanup >= CLEANUP_INTERVAL_MS) {
      const cleanupAt = new Date(now).toISOString();
      const auditCutoff = new Date(now - 90 * 86_400_000).toISOString();
      const challengeCutoff = new Date(now - 24 * 3_600_000).toISOString();
      const rateCutoff = Math.floor(now / 1000) - 2 * 86_400;
      await env.DB.batch([
        env.DB.prepare('DELETE FROM audit_logs WHERE created_at<?').bind(auditCutoff),
        env.DB.prepare('DELETE FROM device_challenges WHERE expires_at<? OR (used_at IS NOT NULL AND used_at<?)').bind(challengeCutoff, challengeCutoff),
        env.DB.prepare('DELETE FROM rate_limits WHERE window_start<?').bind(rateCutoff),
        env.DB.prepare(`INSERT INTO schema_meta(meta_key,meta_value,updated_at) VALUES('last_cleanup_at',?,?)
          ON CONFLICT(meta_key) DO UPDATE SET meta_value=excluded.meta_value,updated_at=excluded.updated_at`).bind(cleanupAt, cleanupAt),
      ]);
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
        message: '请在 Cloudflare Pages 项目 Settings > Bindings 中添加 D1 数据库绑定，变量名必须为 DB，然后重新部署。',
      }, { status: 503 });
    }
    return Response.json({
      success: false,
      code: 'D1_SCHEMA_INIT_FAILED',
      message: 'D1 数据库自动初始化失败，请检查 Pages 的 DB 绑定和 D1 配额。',
    }, { status: 500 });
  }

  return server.fetch(request, env);
}
