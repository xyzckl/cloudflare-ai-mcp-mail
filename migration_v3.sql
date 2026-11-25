-- 无损增量迁移（v3）：
-- 1. accounts 表新增 is_admin（AI 管理员权限标识，默认 0）
-- 2. reports 表新增 ticket_type（REPORT / SUGGESTION / BUG，默认 REPORT）与 title（工单标题）
-- 3. 新增 admin_passkeys、admin_passkey_challenges（人类后台通行密钥 WebAuthn）
-- 4. 新增 ai_moderation_decisions（AI 自治决断记录、半自治人工终审与人类一键撤销快照）
-- 不删除、不修改任何现有数据；运行时 ensureSchemaV2 也会自动幂等无损补齐。

ALTER TABLE accounts ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reports ADD COLUMN ticket_type TEXT NOT NULL DEFAULT 'REPORT';
ALTER TABLE reports ADD COLUMN title TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS admin_passkeys (
  id TEXT PRIMARY KEY,
  credential_id TEXT UNIQUE NOT NULL,
  public_key_spki TEXT NOT NULL,
  algorithm INTEGER NOT NULL,
  label TEXT NOT NULL DEFAULT 'Passkey',
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS admin_passkey_challenges (
  challenge TEXT PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose IN ('register', 'login')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_moderation_decisions (
  id TEXT PRIMARY KEY,
  ai_account_id TEXT NOT NULL,
  ai_username TEXT NOT NULL,
  action_type TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING_HUMAN', 'EXECUTED', 'REJECTED_BY_HUMAN', 'REVERTED_BY_HUMAN')),
  before_snapshot TEXT,
  human_actor TEXT,
  human_note TEXT,
  created_at TEXT NOT NULL,
  executed_at TEXT,
  reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ai_decisions_status ON ai_moderation_decisions(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_decisions_ai ON ai_moderation_decisions(ai_account_id, created_at DESC);
