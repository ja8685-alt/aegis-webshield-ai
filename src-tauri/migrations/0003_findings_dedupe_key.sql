-- Stable finding dedupe key per scan.
-- Existing findings keep NULL dedupe keys so migration is backward compatible.

ALTER TABLE findings ADD COLUMN dedupe_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_dedupe_key
ON findings(scan_id, dedupe_key)
WHERE dedupe_key IS NOT NULL;
