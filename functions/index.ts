import { handlePagesRequest } from '../src/pages';
import type { Env } from '../src/types';

export async function onRequest(context: { request: Request; env: Env }): Promise<Response> {
  return handlePagesRequest(context.request, context.env);
}
