export interface Env {
  DB: D1Database;
  ADMIN_PASSWORD: string;
  SESSION_SECRET: string;
  DEVICE_PROOF_SECRET: string;
  TURNSTILE_SECRET: string;
  LICENSE_SIGNING_PRIVATE_KEY: string;
  APP_NAME?: string;
  TURNSTILE_SITE_KEY?: string;
  LEASE_HOURS?: string;
  BOOTSTRAP_BASE_URL?: string;
}

export type JsonObject = Record<string, unknown>;

export type LicenseRow = {
  id: string;
  license_key: string;
  edition: string;
  status: string;
  license_type: 'permanent' | 'duration' | 'fixed' | string;
  duration_days: number | null;
  expires_at: string | null;
  activated_at: string | null;
  max_devices: number;
};

export type DeviceRow = {
  id: string;
  license_id: string;
  device_id: string;
  public_key: string | null;
  device_name: string | null;
  windows_version: string | null;
  app_version: string | null;
  first_seen_at: string;
  last_seen_at: string;
  revoked_at: string | null;
};

export type ProofPayload = {
  licenseId: string;
  deviceId: string;
  exp: number;
  nonce: string;
};

export type ConfigCheck = {
  ok: boolean;
  missing: string[];
  invalid: string[];
};
