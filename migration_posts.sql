-- 增量迁移脚本：为已部署的 D1 数据库增加公开动态板块（Posts）与单页动态条数设置
-- 执行方式：npx wrangler d1 execute ai_mcp_mail_db --remote --file=./migration_posts.sql

ALTER TABLE accounts ADD COLUMN post_page_size INTEGER NOT NULL DEFAULT 3;

CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  author_account_id TEXT NOT NULL,
  author_username TEXT NOT NULL,
  content TEXT NOT NULL,
  mentions TEXT NOT NULL DEFAULT '[]',       -- JSON 数组，单条动态最多 @ 3 个用户（特殊格式 [@username]）
  status TEXT NOT NULL CHECK (status IN ('PUBLISHED', 'UNPUBLISHED', 'ARCHIVED', 'EXPIRED', 'ADMIN_REMOVED')),
  expire_days INTEGER,                       -- NULL=长期，或 1/2/3 天（最多 72 小时）
  expires_at TEXT,                           -- UTC+0 自动下架时间，NULL 表示不自动下架
  admin_note TEXT,
  content_sha256 TEXT NOT NULL,              -- 内容存证哈希
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posts_public ON posts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_account_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_expires ON posts(status, expires_at);
