import { DatabaseSync } from "node:sqlite";
import { config, ensureDataDirs } from "./config.js";
import { applyPendingRestore } from "./services/backup.js";

ensureDataDirs();
applyPendingRestore();

export const db = new DatabaseSync(config.dbPath);
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  password_hash TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  is_platform_admin INTEGER NOT NULL DEFAULT 0,
  can_create_org INTEGER NOT NULL DEFAULT 0,
  oidc_sub TEXT,
  created_at INTEGER NOT NULL,
  disabled_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT
);

CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  retention_days INTEGER NOT NULL DEFAULT 365,
  created_at INTEGER NOT NULL,
  created_by TEXT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS org_members (
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('owner','admin','member')),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  invite_hash TEXT,
  wrapped_dek TEXT NOT NULL,
  retention_days INTEGER,
  created_by TEXT REFERENCES users(id),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS project_members (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('admin','member')),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, user_id)
);

CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  parent_id TEXT,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'members'
);

CREATE TABLE IF NOT EXISTS folder_acl (
  folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access TEXT NOT NULL CHECK(access IN ('read','edit')),
  PRIMARY KEY (folder_id, user_id)
);

CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_by TEXT NOT NULL,
  current_version INTEGER NOT NULL DEFAULT 0,
  retention_until INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS file_acl (
  file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  access TEXT NOT NULL CHECK(access IN ('read','edit','none')),
  can_delete INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (file_id, user_id)
);

CREATE TABLE IF NOT EXISTS file_versions (
  id TEXT PRIMARY KEY,
  file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  size INTEGER NOT NULL,
  storage_key TEXT NOT NULL,
  checksum TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(file_id, version)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  org_id TEXT,
  project_id TEXT,
  actor_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  meta_json TEXT,
  ip TEXT,
  user_agent TEXT,
  outcome TEXT NOT NULL DEFAULT 'success'
);

CREATE TABLE IF NOT EXISTS oidc_states (
  state TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_events(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_events(project_id);
CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id);
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id);
`);

try {
  db.exec(`
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  scopes_json TEXT NOT NULL DEFAULT '["*"]',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
`);
} catch {
  /* exists */
}

try {
  db.exec(`
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events_json TEXT NOT NULL,
  created_by TEXT REFERENCES users(id),
  created_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  last_status TEXT,
  last_delivery_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(org_id);
`);
} catch {
  /* exists */
}

try {
  db.exec(`ALTER TABLE users ADD COLUMN email_verified_at INTEGER`);
} catch {
  /* already exists */
}

try {
  db.exec(`
CREATE TABLE IF NOT EXISTS email_challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK(purpose IN ('activate','reset')),
  code_hash TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_email_challenges_user ON email_challenges(user_id);
`);
} catch {
  /* exists */
}

// Existing active users are treated as already verified (no re-activation).
try {
  db.exec(`
    UPDATE users SET email_verified_at = COALESCE(email_verified_at, created_at)
    WHERE status = 'active' AND email_verified_at IS NULL
  `);
} catch {
  /* ignore */
}

try {
  db.exec(`ALTER TABLE audit_events ADD COLUMN ip TEXT`);
} catch {
  /* already exists */
}
try {
  db.exec(`ALTER TABLE audit_events ADD COLUMN user_agent TEXT`);
} catch {
  /* already exists */
}
try {
  db.exec(`ALTER TABLE audit_events ADD COLUMN outcome TEXT NOT NULL DEFAULT 'success'`);
} catch {
  /* already exists */
}
try {
  db.exec(`ALTER TABLE users ADD COLUMN can_create_org INTEGER NOT NULL DEFAULT 0`);
} catch {
  /* already exists */
}
try {
  db.exec(`ALTER TABLE file_acl ADD COLUMN can_delete INTEGER NOT NULL DEFAULT 0`);
} catch {
  /* already exists */
}
try {
  db.exec(`ALTER TABLE files ADD COLUMN language TEXT`);
} catch {
  /* already exists */
}
try {
  db.exec(`ALTER TABLE files ADD COLUMN is_code INTEGER NOT NULL DEFAULT 0`);
} catch {
  /* already exists */
}
try {
  db.exec(`ALTER TABLE files ADD COLUMN format_status TEXT`);
} catch {
  /* already exists */
}
try {
  db.exec(`ALTER TABLE files ADD COLUMN diagnostics_json TEXT`);
} catch {
  /* already exists */
}
// Existing org owners keep ability to create orgs
try {
  db.exec(`
    UPDATE users SET can_create_org = 1
    WHERE is_platform_admin = 1
       OR id IN (SELECT user_id FROM org_members WHERE role = 'owner')
  `);
} catch {
  /* ignore */
}

export function now() {
  return Date.now();
}
