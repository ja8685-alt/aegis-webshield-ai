-- Aegis WebShield AI local SQLite schema.
-- This migration is intentionally small and app-owned so the desktop app can
-- run without a Team Server.

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  approval_note TEXT NOT NULL,
  allow_private_network INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  profile TEXT NOT NULL,
  phase TEXT NOT NULL,
  status_message TEXT NOT NULL DEFAULT '',
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  parameter_name TEXT,
  status TEXT NOT NULL DEFAULT 'new',
  evidence_json TEXT NOT NULL,
  remediation TEXT NOT NULL DEFAULT '',
  cwe TEXT,
  owasp_category TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_meters (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  meter_key TEXT NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  used_value INTEGER NOT NULL DEFAULT 0,
  limit_value INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, meter_key, period_start)
);

CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  plan TEXT NOT NULL,
  status TEXT NOT NULL,
  license_key_hash TEXT,
  online_account_id TEXT,
  expires_at TEXT,
  last_checked_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  actor_user_id TEXT,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  metadata_json_redacted TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

