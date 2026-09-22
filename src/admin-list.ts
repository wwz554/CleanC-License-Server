import { effectiveStatusSql } from './license-status';
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

async function validAdminSession(request: Request, env: Env): Promise<boolean> {
  const session = getCookie(request, 'cleanc_session');
  const [payload, signature] = session.split('.');
  if (!payload || !signature) return false;
  if (!safeEqual(signature, await hmac(env.SESSION_SECRET, payload))) return false;

  try {
    const parsed = JSON.parse(decoder.decode(unb64url(payload))) as { exp?: number };
    return typeof parsed.exp === 'number' && parsed.exp > Date.now();
  } catch {
    return false;
  }
}

function positiveInt(value: string | null, fallback: number, max: number): number {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? Math.min(n, max) : fallback;
}

function cleanQuery(value: string | null, max = 100): string {
  return String(value || '').trim().slice(0, max);
}

function likePattern(value: string): string {
  return `%${value.replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_')}%`;
}

export async function handleAdminPaginatedList(
  request: Request,
  env: Env,
): Promise<Response | null> {
  if (request.method !== 'GET') return null;

  const url = new URL(request.url);
  const path = url.pathname;
  if (path !== '/admin/api/licenses' && path !== '/admin/api/devices') return null;

  if (!await validAdminSession(request, env)) {
    return json({ success: false, code: 'UNAUTHORIZED', message: '未授权' }, 401);
  }

  const requestedPage = positiveInt(url.searchParams.get('page'), 1, 1_000_000);
  const pageSize = positiveInt(url.searchParams.get('pageSize'), 10, 50);
  const q = cleanQuery(url.searchParams.get('q'));

  if (path === '/admin/api/licenses') {
    const statusRaw = cleanQuery(url.searchParams.get('status'), 20);
    const status = ['active','disabled','expired','invalid'].includes(statusRaw) ? statusRaw : '';
    const type = cleanQuery(url.searchParams.get('type'),20);
    const binding = cleanQuery(url.searchParams.get('binding'),20);
    const effective = effectiveStatusSql('l');

    const where: string[] = ['l.deleted_at IS NULL'];
    const bindings: unknown[] = [];

    if (q) {
      where.push("l.license_key LIKE ? ESCAPE '\\'");
      bindings.push(likePattern(q));
    }
    if (status) {
      if(status==='invalid') where.push(`(${effective}) <> 'active'`);
      else { where.push(`(${effective}) = ?`); bindings.push(status); }
    }

    if(['permanent','duration','fixed'].includes(type)){where.push('l.license_type=?');bindings.push(type);}
    const bound = 'EXISTS (SELECT 1 FROM devices d WHERE d.license_id=l.id AND d.revoked_at IS NULL)';
    if(binding==='bound')where.push(bound);
    if(binding==='unbound')where.push('NOT '+bound);
    const whereSql = where.join(' AND ');
    const count = await env.DB.prepare(
      `SELECT COUNT(*) AS total FROM licenses l WHERE ${whereSql}`,
    ).bind(...bindings).first<{ total: number }>();

    const total = Number(count?.total || 0);
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const page = Math.min(requestedPage, totalPages);
    const offset = (page - 1) * pageSize;

    const { results } = await env.DB.prepare(`
      SELECT
        l.*,
        ${effective} AS effective_status,
        (
          SELECT COUNT(*)
          FROM devices d
          WHERE d.license_id=l.id AND d.revoked_at IS NULL
        ) AS device_count
      FROM licenses l
      WHERE ${whereSql}
      ORDER BY l.created_at DESC
      LIMIT ? OFFSET ?
    `).bind(...bindings, pageSize, offset).all();

    return json({
      success: true,
      licenses: results,
      pagination: { page, pageSize, total, totalPages },
      filters: { q, status: status || 'all', type, binding },
    });
  }

  const bindingRaw = cleanQuery(url.searchParams.get('binding'), 20);
  const binding = bindingRaw === 'bound' || bindingRaw === 'unbound' ? bindingRaw : '';

  const where: string[] = [];
  const bindings: unknown[] = [];

  if (q) {
    where.push(`(
      l.license_key LIKE ? ESCAPE '\\'
      OR d.device_id LIKE ? ESCAPE '\\'
      OR COALESCE(d.device_name,'') LIKE ? ESCAPE '\\'
    )`);
    const pattern = likePattern(q);
    bindings.push(pattern, pattern, pattern);
  }
  if (binding === 'bound') where.push('d.revoked_at IS NULL');
  if (binding === 'unbound') where.push('d.revoked_at IS NOT NULL');

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const count = await env.DB.prepare(`
    SELECT COUNT(*) AS total
    FROM devices d
    JOIN licenses l ON l.id=d.license_id
    ${whereSql}
  `).bind(...bindings).first<{ total: number }>();

  const total = Number(count?.total || 0);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(requestedPage, totalPages);
  const offset = (page - 1) * pageSize;

  const { results } = await env.DB.prepare(`
    SELECT d.*,l.license_key
    FROM devices d
    JOIN licenses l ON l.id=d.license_id
    ${whereSql}
    ORDER BY d.last_seen_at DESC
    LIMIT ? OFFSET ?
  `).bind(...bindings, pageSize, offset).all();

  return json({
    success: true,
    devices: results,
    pagination: { page, pageSize, total, totalPages },
    filters: { q, binding: binding || 'all' },
  });
}

