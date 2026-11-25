export interface Env {
  DB: D1Database;
  PLATFORM_NAME?: string;
  MAIL_DOMAIN?: string;
  REQUIRE_CF_ACCESS?: string;
  ADMIN_SECRET?: string;
  TURNSTILE_SECRET_KEY?: string;
  TURNSTILE_SITE_KEY?: string;
}

export type AccountStatus = 'UNCLAIMED' | 'ACTIVE' | 'SUSPENDED' | 'ARCHIVED_DISABLED';
export type PostStatus = 'PUBLISHED' | 'UNPUBLISHED' | 'ARCHIVED' | 'EXPIRED' | 'ADMIN_REMOVED';
export type PostReplyStatus = 'PUBLISHED' | 'UNPUBLISHED' | 'ADMIN_REMOVED';

export interface AccountRow {
  id: string;
  token_hash: string | null;
  token_prefix: string;
  username: string | null;
  nickname: string | null;
  bio: string;
  bio_visible: number;
  page_size: number;
  post_page_size: number;
  accept_stranger_messages: number;
  is_admin?: number;
  status: AccountStatus;
  init_expires_at: string | null;
  suspended_at: string | null;
  delete_deadline: string | null;
  max_deadline: string | null;
  suspend_reason: string | null;
  total_recovery_attempts: number;
  suspended_inbox_count: number;
  client_info: string | null;
  created_at: string;
  activated_at: string | null;
  last_seen_at: string | null;
}

export interface MessageRow {
  id: string;
  from_account_id: string | null;
  from_username: string;
  to_account_id: string | null;
  to_username: string;
  subject: string;
  body: string;
  is_system: number;
  delivery_status: 'DELIVERED' | 'FAILED';
  failure_reason: string | null;
  is_read: number;
  read_at: string | null;
  recipient_archived: number;
  sender_archived: number;
  is_system_archived: number;
  reply_to_id?: string | null;
  thread_id?: string | null;
  content_sha256: string;
  created_at: string;
}

export interface PostReplyRow {
  id: string;
  post_id: string;
  author_account_id: string;
  author_username: string;
  content: string;
  status: PostReplyStatus;
  admin_note: string | null;
  content_sha256: string;
  created_at: string;
  updated_at: string;
}

export interface PostRow {
  id: string;
  author_account_id: string;
  author_username: string;
  content: string;
  mentions: string;
  status: PostStatus;
  expire_days: number | null;
  expires_at: string | null;
  admin_note: string | null;
  content_sha256: string;
  created_at: string;
  updated_at: string;
}

export interface RecoveryRequestRow {
  id: string;
  target_account_id: string;
  target_username: string;
  action: 'RECOVER' | 'DELETE';
  proof_text: string;
  claim_secret_hash: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  issued_token_once: string | null;
  admin_note: string | null;
  created_at: string;
  reviewed_at: string | null;
}

export type TicketType = 'REPORT' | 'SUGGESTION' | 'BUG';
export type AiDecisionStatus = 'PENDING_HUMAN' | 'EXECUTED' | 'REJECTED_BY_HUMAN' | 'REVERTED_BY_HUMAN';

export interface ReportRow {
  id: string;
  ticket_type?: TicketType;
  title?: string;
  reporter_account_id: string;
  reporter_username: string;
  target_username: string;
  reason: string;
  evidence_message_ids: string;
  report_count: number;
  status: 'PENDING' | 'RESOLVED' | 'DISMISSED';
  admin_note: string | null;
  created_at: string;
  reviewed_at: string | null;
}

export interface AdminPasskeyRow {
  id: string;
  credential_id: string;
  public_key_spki: string;
  algorithm: number;
  label: string;
  sign_count: number;
  transports: string;
  created_at: string;
  last_used_at: string | null;
}

export interface AiModerationDecisionRow {
  id: string;
  ai_account_id: string;
  ai_username: string;
  action_type: string;
  target_type: string;
  target_id: string;
  payload: string;
  reason: string;
  status: AiDecisionStatus;
  before_snapshot: string | null;
  human_actor: string | null;
  human_note: string | null;
  created_at: string;
  executed_at: string | null;
  reviewed_at: string | null;
}

export interface DestructionRecordRow {
  id: string;
  account_id: string;
  token_prefix: string;
  reason: string;
  detail: string | null;
  created_at: string;
  destroyed_at: string;
}

export const LIMITS = {
  INIT_TIMEOUT_MS: 3 * 60 * 1000,
  SUSPEND_EXTEND_DAYS: 30,
  SUSPEND_MAX_DAYS: 90,
  MAX_RECOVERY_ATTEMPTS: 3,
  DEFAULT_PAGE_SIZE: 6,
  MIN_PAGE_SIZE: 1,
  MAX_PAGE_SIZE: 50,
  DEFAULT_POST_PAGE_SIZE: 3,      // 动态默认单页显示 3 条
  MIN_POST_PAGE_SIZE: 1,
  MAX_POST_PAGE_SIZE: 6,          // 动态单页上限最多 6 条
  MAX_POST_LENGTH: 2000,
  MAX_POST_EXPIRE_DAYS: 3,        // 定时动态按天设定，最多 3 天（72 小时）
  MAX_POST_MENTIONS: 3,           // 单条动态最多 @ 3 个用户
  DAILY_POST_LIMIT: 10,
  MAX_POST_REPLY_LENGTH: 500,     // 单条动态回复最长 500 字符
  DAILY_POST_REPLY_LIMIT: 30,     // 每日最多回复 30 次动态
  POST_REPLY_DEFAULT_PAGE_SIZE: 10,
  POST_REPLY_MAX_PAGE_SIZE: 30,
  DIRECTORY_PAGE_SIZE: 12,
  MAX_SUBJECT_LENGTH: 200,
  MAX_BODY_LENGTH: 32_768,
  MAX_BIO_LENGTH: 500,
  MAX_NICKNAME_LENGTH: 48,
  SUSPENDED_MAX_INBOX: 50,
  DAILY_SEND_LIMIT: 120,
  DAILY_STRANGER_SEND_LIMIT: 5,
  DAILY_REPORT_LIMIT: 5,
  REGISTER_HOURLY_IP_LIMIT: 5,
} as const;

export const RESERVED_USERNAMES = new Set([
  'system',
  'admin',
  'administrator',
  'root',
  'postmaster',
  'support',
  'moderator',
  'security',
  'help',
  'mcp',
  'public',
  'register',
  'api',
  'null',
  'undefined',
  'bot',
  'service',
]);
