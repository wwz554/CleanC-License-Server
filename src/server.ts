import { adminPage } from './admin';
import { adminApi, login } from './admin-api';
import { activate, challenge, validateOrRefresh, verifyDevice } from './license';
import type { Env, JsonObject } from './types';
import { canonicalBaseUrl, checkRuntimeConfig, fail, html, json, nowIso, signObject } from './common';

const ROUTE_METHODS: Record<string, string[]> = {
  '/api/v1/health': ['GET'],
  '/api/v1/meta': ['GET'],
  '/bootstrap/v1/config': ['GET'],
  '/api/v1/license/activate': ['POST'],
  '/api/v1/license/validate': ['POST'],
  '/api/v1/license/refresh': ['POST'],
  '/api/v1/device/challenge': ['POST'],
  '/api/v1/device/verify': ['POST'],
  '/admin/api/login': ['POST'],
};

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      const config = await checkRuntimeConfig(env);
      if (path === '/api/v1/health' && req.method === 'GET') {
        return json({
          status: config.ok ? 'ok' : 'degraded',
          service: 'cleanc-license-server',
          apiVersion: 3,
          configured: config.ok,
          ...(config.ok ? {} : { missing: config.missing, invalid: config.invalid }),
        }, config.ok ? 200 : 503);
      }
      if (!config.ok) {
        return fail('SERVER_NOT_CONFIGURED', '生产环境变量或 Secret 未完整配置，请先检查 /api/v1/health', 503);
      }

      if (path === '/api/v1/meta' && req.method === 'GET') {
        return json({
          appName: env.APP_NAME || 'CleanC',
          apiVersion: 3,
          canonicalBaseUrl: await canonicalBaseUrl(req, env),
          signatureAlgorithm: 'ECDSA_P256_SHA256',
          signatureFormat: 'IEEE_P1363',
        });
      }
      if (path === '/bootstrap/v1/config' && req.method === 'GET') {
        const payload: JsonObject = {
          apiVersion: 3,
          canonicalBaseUrl: await canonicalBaseUrl(req, env),
          issuedAt: nowIso(),
        };
        return json({ ...payload, ...await signObject(env, payload) });
      }
      if (path === '/api/v1/license/activate' && req.method === 'POST') return activate(req, env);
      if (path === '/api/v1/license/validate' && req.method === 'POST') return validateOrRefresh(req, env, 'validate');
      if (path === '/api/v1/license/refresh' && req.method === 'POST') return validateOrRefresh(req, env, 'refresh');
      if (path === '/api/v1/device/challenge' && req.method === 'POST') return challenge(req, env);
      if (path === '/api/v1/device/verify' && req.method === 'POST') return verifyDevice(req, env);
      if (path === '/admin/api/login' && req.method === 'POST') return login(req, env);
      if (path.startsWith('/admin/api/')) return adminApi(req, env, path);
      if (path === '/admin' || path === '/admin/' || path === '/admin/login') return html(adminPage(env.TURNSTILE_SITE_KEY || ''));
      if (path === '/') return Response.redirect(new URL('/admin', req.url).toString(), 302);

      if (ROUTE_METHODS[path] && !ROUTE_METHODS[path].includes(req.method)) {
        return json({ success: false, code: 'METHOD_NOT_ALLOWED', message: '请求方法不允许' }, 405, { allow: ROUTE_METHODS[path].join(', ') });
      }
      return fail('NOT_FOUND', '资源不存在', 404);
    } catch (error) {
      console.error('request failed', error);
      if (error instanceof Error) {
        if (error.message === 'INVALID_CONTENT_TYPE') return fail('INVALID_CONTENT_TYPE', '请求必须使用 application/json', 415);
        if (error.message === 'PAYLOAD_TOO_LARGE') return fail('PAYLOAD_TOO_LARGE', '请求体过大', 413);
        if (error.message === 'INVALID_JSON') return fail('INVALID_JSON', 'JSON 请求格式无效', 400);
      }
      return fail('SERVER_ERROR', '服务器内部错误', 500);
    }
  },
};
