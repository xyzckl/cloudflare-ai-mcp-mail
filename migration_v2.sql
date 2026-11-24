-- 无损增量迁移（v2）：为已有数据库补充邮件会话线程字段（reply_to_id、thread_id）与公开动态回复表（post_replies）
-- 不删除、不修改任何现有数据；站点自定义设置均复用已有的 system_settings 表。

ALTER TABLE messages ADD COLUMN reply_to_id TEXT;
ALTER TABLE messages ADD COLUMN thread_id TEXT;
CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(thread_id, created_at ASC);

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
