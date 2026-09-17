import { handleAppRequest } from '../src/router';
import type { Env } from '../src/worker';

export async function onRequest(context: { request: Request; env: Env }): Promise<Response> {
  return handleAppRequest(context.request, context.env);
}
