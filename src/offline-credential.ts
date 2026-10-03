import type { Env } from './worker';
import { signObject } from './production';

// Internal only: callers must first authenticate activation or device possession.
// Never sign fields supplied directly by an HTTP request.
export async function offlineCredential(env: Env, lease: Record<string, unknown>, requestHash = '', codeHash = '', challengeNonce = '') {
 if (lease.renewalProtocol !== 'challenge-refresh' || lease.version !== 4 || lease.apiVersion !== 3 ||
     typeof lease.deviceId !== 'string' || typeof lease.licenseId !== 'string' ||
     typeof lease.serverTime !== 'string' || !Array.isArray(lease.features)) throw Error('invalid source lease');
 return signObject(env, {
  version: 1, app: 'CleanC', purpose: 'offline-entitlement-v1', requestHash, codeHash, challengeNonce,
  lease: {...lease, renewalProtocol: 'offline-v3', leaseHours: 0,
   expiresAt: lease.licenseExpiresAt ?? '9999-12-31T23:59:59.9999999+00:00'}
 });
}
