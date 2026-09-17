import { handleProductionRequest } from '../src/production';
import type { Env } from '../src/worker';

export async function onRequest(context: { request: Request; env: Env }): Promise<Response> {
  return handleProductionRequest(context.request, context.env);
}
