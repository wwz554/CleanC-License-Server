/** Derive validity without changing administrative enable/disable state. */
export function effectiveStatusSql(alias: string): string {
  return `CASE WHEN ${alias}.status <> 'active' THEN 'disabled'
    WHEN ${alias}.license_type = 'permanent' THEN 'active'
    WHEN ${alias}.license_type = 'duration' AND ${alias}.activated_at IS NULL AND ${alias}.expires_at IS NULL THEN 'active'
    WHEN julianday(${alias}.expires_at) > julianday('now') THEN 'active'
    ELSE 'expired' END`;
}
