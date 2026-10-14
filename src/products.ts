import type { Env } from './worker';

export type Product = 'CleanC' | 'NetIME';
export const PRODUCTS: readonly Product[] = ['CleanC', 'NetIME'];
let productSchema: Promise<void> | null = null;

// Existing codes retain their original product. No code or binding is recreated.
export async function ensureProductSchema(env: Env): Promise<void> {
  if (!productSchema) productSchema = (async () => {
    const columns = await env.DB.prepare('PRAGMA table_info(licenses)').all<{ name: string }>();
    if (!columns.results.some(c => c.name === 'product')) {
      try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN product TEXT NOT NULL DEFAULT 'CleanC'").run(); }
      catch (error) {
        const again = await env.DB.prepare('PRAGMA table_info(licenses)').all<{ name: string }>();
        if (!again.results.some(c => c.name === 'product')) throw error;
      }
    }
    await env.DB.batch([
      env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_license_product ON licenses(product,created_at)"),
      env.DB.prepare("CREATE TRIGGER IF NOT EXISTS trg_license_product_insert BEFORE INSERT ON licenses WHEN NEW.product NOT IN ('CleanC','NetIME') BEGIN SELECT RAISE(ABORT,'INVALID_PRODUCT'); END"),
      env.DB.prepare("CREATE TRIGGER IF NOT EXISTS trg_license_product_immutable BEFORE UPDATE OF product ON licenses WHEN NEW.product IS NOT OLD.product BEGIN SELECT RAISE(ABORT,'LICENSE_PRODUCT_IMMUTABLE'); END"),
    ]);
  })().catch(error => { productSchema = null; throw error; });
  await productSchema;
}

export function requestedProduct(body: Record<string, unknown>): Product | null {
  // Old CleanC clients did not send a product. They can only use CleanC codes.
  const product = body.product === undefined ? 'CleanC' : body.product;
  return product === 'CleanC' || product === 'NetIME' ? product : null;
}

export function productMismatch(body: Record<string, unknown>, stored: string): Response | null {
  const product = requestedProduct(body), device = String(body.deviceId || '').trim();
  if (product !== stored || (product === 'NetIME') !== device.startsWith('NETIME-')) {
    return Response.json({ success: false, code: 'LICENSE_PRODUCT_MISMATCH', message: '授权码所属产品与客户端不匹配：CleanC 与网工拼音必须使用各自的授权码。' },
      { status: 403, headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
  }
  return null;
}

export function productFeatures(product: string): string[] {
  if (product === 'NetIME') return ['panel', 'cards', 'diagnostics', 'learning'];
  if (product === 'CleanC') return ['clean', 'scan', 'optimize'];
  throw new Error('INVALID_PRODUCT');
}

export function productPrefix(product: Product): string { return product === 'NetIME' ? 'NETIME' : 'CLC'; }
