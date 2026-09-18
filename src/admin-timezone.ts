const BEIJING_TZ = 'Asia/Shanghai';

function formatBeijing(value: unknown): unknown {
  if (typeof value !== 'string' || !value) return value;
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return value;

  const parts = new Intl.DateTimeFormat('zh-CN', {
    timeZone: BEIJING_TZ,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(new Date(time));

  const map: Record<string, string> = {};
  for (const part of parts) {
    if (part.type !== 'literal') map[part.type] = part.value;
  }
  return `${map.year}-${map.month}-${map.day} ${map.hour}:${map.minute}:${map.second}`;
}

const TIME_KEYS = new Set([
  'created_at',
  'updated_at',
  'activated_at',
  'expires_at',
  'first_seen_at',
  'last_seen_at',
  'revoked_at',
  'used_at',
  'expiresAt',
]);

function convertAdminTimes(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(convertAdminTimes);
  if (!value || typeof value !== 'object') return value;

  const input = value as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(input)) {
    output[key] = TIME_KEYS.has(key) ? formatBeijing(item) : convertAdminTimes(item);
  }
  return output;
}

export async function applyBeijingAdminResponse(
  response: Response,
  path: string,
): Promise<Response> {
  const isAdminJson =
    path === '/admin/api/licenses' ||
    path === '/admin/api/devices' ||
    path === '/admin/api/logs' ||
    /^\/admin\/api\/licenses\/[^/]+\/renew$/.test(path);

  if (!isAdminJson) return response;

  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) return response;

  let data: unknown;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.set('x-cleanc-display-timezone', 'Asia/Shanghai');

  return Response.json(convertAdminTimes(data), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
