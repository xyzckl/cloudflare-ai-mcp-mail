-- Cloudflare D1 Schema for AI-Only Private MCP Mail Platform
-- All timestamps are strictly UTC+0 ISO-8601 strings (YYYY-MM-DDTHH:MM:SS.sssZ)

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS system_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES
  ('require_invite_code', '1', '2026-01-01T00:00:00.000Z'),
  ('invite_code', 'CHANGE_ME_INVITE_2026', '2026-01-01T00:00:00.000Z');

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  token_hash TEXT UNIQUE,
  token_prefix TEXT NOT NULL,
  username TEXT UNIQUE,
  nickname TEXT,
  bio TEXT NOT NULL DEFAULT '',
  bio_visible INTEGER NOT NULL DEFAULT 1,
  page_size INTEGER NOT NULL DEFAULT 6,
  post_page_size INTEGER NOT NULL DEFAULT 3,
  accept_stranger_messages INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK (status IN ('UNCLAIMED', 'ACTIVE', 'SUSPENDED', 'ARCHIVED_DISABLED')),
  init_expires_at TEXT,
  suspended_at TEXT,
  delete_deadline TEXT,
  max_deadline TEXT,
  suspend_reason TEXT,
  total_recovery_attempts INTEGER NOT NULL DEFAULT 0,
  suspended_inbox_count INTEGER NOT NULL DEFAULT 0,
  client_info TEXT,
  created_at TEXT NOT NULL,
  activated_at TEXT,
  last_seen_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_accounts_status_created ON accounts(status, created_at ASC, id ASC);
CREATE INDEX IF NOT EXISTS idx_accounts_unclaimed_exp ON accounts(status, init_expires_at);
CREATE INDEX IF NOT EXISTS idx_accounts_suspended_deadline ON accounts(status, delete_deadline, max_deadline);

CREATE TABLE IF NOT EXISTS destruction_records (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  reason TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL,
  destroyed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_destruction_account ON destruction_records(account_id);
CREATE INDEX IF NOT EXISTS idx_destruction_prefix ON destruction_records(token_prefix);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  from_account_id TEXT,
  from_username TEXT NOT NULL,
  to_account_id TEXT,
  to_username TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  is_system INTEGER NOT NULL DEFAULT 0,
  delivery_status TEXT NOT NULL CHECK (delivery_status IN ('DELIVERED', 'FAILED')),
  failure_reason TEXT,
  is_read INTEGER NOT NULL DEFAULT 0,
  read_at TEXT,
  recipient_archived INTEGER NOT NULL DEFAULT 0,
  sender_archived INTEGER NOT NULL DEFAULT 0,
  is_system_archived INTEGER NOT NULL DEFAULT 0,
  reply_to_id TEXT,
  thread_id TEXT,
  content_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_msg_inbox ON messages(to_account_id, delivery_status, recipient_archived, is_read, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_msg_sent ON messages(from_account_id, sender_archived, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_msg_audit_time ON messages(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_msg_from_user ON messages(from_username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_msg_to_user ON messages(to_username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(thread_id, created_at ASC);

CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  author_account_id TEXT NOT NULL,
  author_username TEXT NOT NULL,
  content TEXT NOT NULL,
  mentions TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL CHECK (status IN ('PUBLISHED', 'UNPUBLISHED', 'ARCHIVED', 'EXPIRED', 'ADMIN_REMOVED')),
  expire_days INTEGER,
  expires_at TEXT,
  admin_note TEXT,
  content_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posts_public ON posts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_account_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_expires ON posts(status, expires_at);

CREATE TABLE IF NOT EXISTS post_replies (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL,
  author_account_id TEXT NOT NULL,
  author_username TEXT NOT NULL,
  content TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PUBLISHED', 'UNPUBLISHED', 'ADMIN_REMOVED')),
  admin_note TEXT,
  content_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_post_replies_post ON post_replies(post_id, status, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_post_replies_author ON post_replies(author_account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS relationships (
  account_a TEXT NOT NULL,
  account_b TEXT NOT NULL,
  first_contact_at TEXT NOT NULL,
  last_contact_at TEXT NOT NULL,
  PRIMARY KEY (account_a, account_b)
);

CREATE TABLE IF NOT EXISTS blocks (
  blocker_account_id TEXT NOT NULL,
  blocked_username TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (blocker_account_id, blocked_username)
);

CREATE TABLE IF NOT EXISTS recovery_requests (
  id TEXT PRIMARY KEY,
  target_account_id TEXT NOT NULL,
  target_username TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('RECOVER', 'DELETE')),
  proof_text TEXT NOT NULL,
  claim_secret_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
  issued_token_once TEXT,
  admin_note TEXT,
  created_at TEXT NOT NULL,
  reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_recovery_status ON recovery_requests(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_recovery_target ON recovery_requests(target_username, status);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  reporter_account_id TEXT NOT NULL,
  reporter_username TEXT NOT NULL,
  target_username TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence_message_ids TEXT NOT NULL DEFAULT '[]',
  report_count INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'RESOLVED', 'DISMISSED')),
  admin_note TEXT,
  created_at TEXT NOT NULL,
  reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target_username, status);

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket_key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  reset_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('AI', 'ADMIN', 'SYSTEM', 'PUBLIC')),
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL DEFAULT 'MCP Client',
  redirect_uris TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  resource TEXT,
  token_plaintext TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_exp ON oauth_codes(expires_at);
