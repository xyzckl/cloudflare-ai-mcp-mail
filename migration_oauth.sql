-- 增量迁移脚本：为已创建的 D1 数据库补充 MCP OAuth 2.1 自动发现与授权表
-- 执行方式：npx wrangler d1 execute ai_mcp_mail_db --remote --file=./migration_oauth.sql

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL DEFAULT 'MCP Client',
  redirect_uris TEXT NOT NULL,              -- JSON 数组
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  resource TEXT,
  token_plaintext TEXT NOT NULL,            -- 一次性换取后立即删除整行
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_exp ON oauth_codes(expires_at);
