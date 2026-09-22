import { handleTurnstileAppRequest } from '../src/router-turnstile';
import type { Env } from '../src/worker';

export async function onRequest(context: { request: Request; env: Env }): Promise<Response> {
  return handleTurnstileAppRequest(context.request, context.env);
}

