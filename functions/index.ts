import { handlePagesRequest } from '../src/pages';
import type { Env } from '../src/worker';

export const onRequest: PagesFunction<Env> = async (context) => {
  return handlePagesRequest(context.request, context.env);
};
