ALTER TABLE device_challenges ADD COLUMN license_id TEXT;
CREATE INDEX IF NOT EXISTS idx_challenges_license_device ON device_challenges(license_id, device_id, created_at DESC);
