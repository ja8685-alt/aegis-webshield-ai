-- Imported API endpoint candidates for approved targets.
-- These records are generated from OpenAPI documents or future crawlers and
-- remain non-secret scan scheduling metadata.

CREATE TABLE IF NOT EXISTS target_endpoints (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  url TEXT NOT NULL,
  operation_id TEXT,
  parameters_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(target_id, method, path)
);
