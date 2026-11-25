import { Env, LIMITS, RESERVED_USERNAMES } from './types';

/** 返回严格的 UTC+0 ISO-8601 时间字符串 */
export function nowUtcIso(date: Date = new Date()): string {
  return date.toISOString();
}

export function addMsIso(baseIso: string, ms: number): string {
  return new Date(Date.parse(baseIso) + ms).toISOString();
}

export function addDaysIso(baseIso: string, days: number): string {
  return addMsIso(baseIso, days * 24 * 60 * 60 * 1000);
}

export function minIso(a: string, b: string): string {
  return Date.parse(a) <= Date.parse(b) ? a : b;
}

/** 将 YYYY-MM 解析为 UTC+0 的左闭右开起止时间 */
export function parseUtcMonthRange(month: string): { start: string; end: string } | null {
  const m = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(month.trim());
  if (!m) return null;
  const year = Number(m[1]);
  const mon = Number(m[2]); // 1..12
  const start = new Date(Date.UTC(year, mon - 1, 1, 0, 0, 0, 0)).toISOString();
  const end = new Date(Date.UTC(year, mon, 1, 0, 0, 0, 0)).toISOString();
  return { start, end };
}

/** 校验并归一化 UTC+0 ISO 时间字符串 */
export function normalizeUtcIso(input: string): string | null {
  const ts = Date.parse(input);
  if (Number.isNaN(ts)) return null;
  return new Date(ts).toISOString();
}

export function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function generateId(prefix: string): string {
  return `${prefix}_${randomHex(12)}`;
}

export function generateCredentialToken(): { token: string; prefix: string } {
  const raw = randomHex(28); // 224-bit entropy
  const token = `aimail_sk_${raw}`;
  const prefix = token.slice(0, 18); // aimail_sk_ + 8 hex chars
  return { token, prefix };
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

export function validateUsername(raw: string): { ok: true; username: string } | { ok: false; error: string } {
  const username = raw.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username)) {
    return {
      ok: false,
      error: '用户名必须为 3~32 位小写字母、数字、点、下划线或短横线，且以字母或数字开头。',
    };
  }
  if (RESERVED_USERNAMES.has(username)) {
    return { ok: false, error: `用户名 "${username}" 为系统保留词，不可注册。` };
  }
  return { ok: true, username };
}

export function validateNickname(raw: string): { ok: true; nickname: string } | { ok: false; error: string } {
  const nickname = raw.trim();
  if (nickname.length < 1 || nickname.length > LIMITS.MAX_NICKNAME_LENGTH) {
    return { ok: false, error: `昵称长度需在 1~${LIMITS.MAX_NICKNAME_LENGTH} 个字符之间。` };
  }
  return { ok: true, nickname };
}

export function validateBio(raw: string): { ok: true; bio: string } | { ok: false; error: string } {
  const bio = raw.trim();
  if (bio.length > LIMITS.MAX_BIO_LENGTH) {
    return { ok: false, error: `个人简介不能超过 ${LIMITS.MAX_BIO_LENGTH} 个字符。` };
  }
  return { ok: true, bio };
}

/** 对不可信外部内容（邮件正文、他人简介）做提示词注入隔离包裹 */
export function wrapUntrustedContent(tag: 'email_body' | 'user_bio' | 'post_content', sender: string, content: string): string {
  const safeSender = sender.replace(/[^a-zA-Z0-9._@-]/g, '');
  const escaped = content.replace(/<\/untrusted_/gi, '&lt;/untrusted_');
  return `<external_${tag} sender="${safeSender}" source="peer_message">\n${escaped}\n</external_${tag}>`;
}

export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function jsonResponse(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...extraHeaders,
    },
  });
}

export function htmlResponse(html: string, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      ...extraHeaders,
    },
  });
}

export async function getSystemSetting(env: Env, key: string, fallback = ''): Promise<string> {
  const row = await env.DB.prepare('SELECT value FROM system_settings WHERE key = ?')
    .bind(key)
    .first<{ value: string }>();
  return row ? row.value : fallback;
}

export async function setSystemSetting(env: Env, key: string, value: string): Promise<void> {
  const now = nowUtcIso();
  await env.DB.prepare(
    `INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
  )
    .bind(key, value, now)
    .run();
}

export async function deleteSystemSetting(env: Env, key: string): Promise<void> {
  await env.DB.prepare('DELETE FROM system_settings WHERE key = ?').bind(key).run();
}

/** 读取当前生效的站点名称：D1 自定义 > wrangler.toml 环境变量 > 默认值 */
export async function getPlatformName(env: Env): Promise<string> {
  const custom = (await getSystemSetting(env, 'platform_name', '')).trim();
  if (custom) return custom;
  return (env.PLATFORM_NAME || '').trim() || 'AI Private MCP Mail';
}

/** 读取当前自定义 Logo 与版本号（用于 /favicon.ico 缓存破除） */
export async function getSiteLogoMeta(env: Env): Promise<{ logo: string; version: string }> {
  const row = await env.DB.prepare('SELECT value, updated_at FROM system_settings WHERE key = ?')
    .bind('site_logo')
    .first<{ value: string; updated_at: string }>();
  if (!row || !row.value.trim()) {
    return { logo: '', version: 'default' };
  }
  return {
    logo: row.value.trim(),
    version: encodeURIComponent(row.updated_at || 'custom'),
  };
}

const ALLOWED_LOGO_DATA_RE = /^data:image\/(png|jpeg|jpg|webp|svg\+xml|x-icon|vnd\.microsoft\.icon);base64,[A-Za-z0-9+/=]+$/i;
const MAX_LOGO_DATA_LENGTH = 180_000; // ~128KB 原始图片转 base64

export function validateSiteLogo(raw: string): { ok: true; value: string } | { ok: false; error: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { ok: true, value: '' };

  if (trimmed.startsWith('data:image/')) {
    if (trimmed.length > MAX_LOGO_DATA_LENGTH) {
      return { ok: false, error: '上传的 Logo 图片过大，请压缩至 128 KB 以内（支持 PNG/SVG/WebP/ICO/JPG）。' };
    }
    if (!ALLOWED_LOGO_DATA_RE.test(trimmed)) {
      return { ok: false, error: '不支持的 Base64 图片格式，仅允许 PNG、JPG、WebP、SVG 或 ICO。' };
    }
    return { ok: true, value: trimmed };
  }

  try {
    const u = new URL(trimmed);
    if (u.protocol !== 'https:') {
      return { ok: false, error: '外部 Logo 链接必须使用 https:// 协议。' };
    }
    if (trimmed.length > 1024) {
      return { ok: false, error: 'Logo 链接长度不能超过 1024 字符。' };
    }
    return { ok: true, value: trimmed };
  } catch {
    return { ok: false, error: '请输入有效的 https:// 图片链接，或通过本地上传选择图片。' };
  }
}

export interface EffectiveLimits {
  daily_send_limit: number;
  daily_stranger_send_limit: number;
  daily_post_limit: number;
  daily_report_limit: number;
  register_hourly_ip_limit: number;
  init_timeout_seconds: number;
}

function parseIntClamped(raw: string | undefined, fallback: number, min: number, max: number): number {
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

/** 读取可被 system_settings 覆盖的核心限流与初始化超时参数 */
export async function getEffectiveLimits(env: Env): Promise<EffectiveLimits> {
  const rows = await env.DB.prepare(
    `SELECT key, value FROM system_settings WHERE key IN (
       'limit_daily_send', 'limit_daily_stranger_send', 'limit_daily_post',
       'limit_daily_report', 'limit_register_hourly_ip', 'limit_init_timeout_sec'
     )`
  ).all<{ key: string; value: string }>();
  const map: Record<string, string> = {};
  for (const r of rows.results ?? []) map[r.key] = r.value;

  return {
    daily_send_limit: parseIntClamped(map.limit_daily_send, LIMITS.DAILY_SEND_LIMIT, 1, 5000),
    daily_stranger_send_limit: parseIntClamped(map.limit_daily_stranger_send, LIMITS.DAILY_STRANGER_SEND_LIMIT, 0, 500),
    daily_post_limit: parseIntClamped(map.limit_daily_post, LIMITS.DAILY_POST_LIMIT, 1, 200),
    daily_report_limit: parseIntClamped(map.limit_daily_report, LIMITS.DAILY_REPORT_LIMIT, 1, 100),
    register_hourly_ip_limit: parseIntClamped(map.limit_register_hourly_ip, LIMITS.REGISTER_HOURLY_IP_LIMIT, 1, 200),
    init_timeout_seconds: parseIntClamped(map.limit_init_timeout_sec, Math.floor(LIMITS.INIT_TIMEOUT_MS / 1000), 60, 3600),
  };
}

let schemaV2Ensured = false;

/**
 * 无损自动补齐 v2 + v3 表结构（幂等、只增不删，保障老服务器零停机无损升级）：
 * - v2: messages 补齐 reply_to_id、thread_id；创建 post_replies 表
 * - v3: accounts 补齐 is_admin；reports 补齐 ticket_type、title；创建 admin_passkeys、admin_passkey_challenges、ai_moderation_decisions 表
 */
export async function ensureSchemaV2(env: Env): Promise<void> {
  if (schemaV2Ensured) return;
  try {
    const [msgCols, accCols, repCols] = await Promise.all([
      env.DB.prepare('PRAGMA table_info(messages)').all<{ name: string }>(),
      env.DB.prepare('PRAGMA table_info(accounts)').all<{ name: string }>(),
      env.DB.prepare('PRAGMA table_info(reports)').all<{ name: string }>(),
    ]);
    const msgNames = new Set((msgCols.results ?? []).map((c) => c.name));
    if (!msgNames.has('reply_to_id')) {
      await env.DB.prepare('ALTER TABLE messages ADD COLUMN reply_to_id TEXT').run().catch(() => {});
    }
    if (!msgNames.has('thread_id')) {
      await env.DB.prepare('ALTER TABLE messages ADD COLUMN thread_id TEXT').run().catch(() => {});
    }
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(thread_id, created_at ASC)').run().catch(() => {});

    const accNames = new Set((accCols.results ?? []).map((c) => c.name));
    if (!accNames.has('is_admin')) {
      await env.DB.prepare('ALTER TABLE accounts ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0').run().catch(() => {});
    }

    const repNames = new Set((repCols.results ?? []).map((c) => c.name));
    if (!repNames.has('ticket_type')) {
      await env.DB.prepare("ALTER TABLE reports ADD COLUMN ticket_type TEXT NOT NULL DEFAULT 'REPORT'").run().catch(() => {});
    }
    if (!repNames.has('title')) {
      await env.DB.prepare("ALTER TABLE reports ADD COLUMN title TEXT NOT NULL DEFAULT ''").run().catch(() => {});
    }

    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS post_replies (
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
       )`
    ).run().catch(() => {});
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_post_replies_post ON post_replies(post_id, status, created_at ASC)').run().catch(() => {});
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_post_replies_author ON post_replies(author_account_id, created_at DESC)').run().catch(() => {});

    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS admin_passkeys (
         id TEXT PRIMARY KEY,
         credential_id TEXT UNIQUE NOT NULL,
         public_key_spki TEXT NOT NULL,
         algorithm INTEGER NOT NULL,
         label TEXT NOT NULL DEFAULT 'Passkey',
         sign_count INTEGER NOT NULL DEFAULT 0,
         transports TEXT NOT NULL DEFAULT '[]',
         created_at TEXT NOT NULL,
         last_used_at TEXT
       )`
    ).run().catch(() => {});

    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS admin_passkey_challenges (
         challenge TEXT PRIMARY KEY,
         purpose TEXT NOT NULL CHECK (purpose IN ('register', 'login')),
         expires_at TEXT NOT NULL,
         created_at TEXT NOT NULL
       )`
    ).run().catch(() => {});

    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS ai_moderation_decisions (
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
       )`
    ).run().catch(() => {});
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_ai_decisions_status ON ai_moderation_decisions(status, created_at DESC)').run().catch(() => {});
    await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_ai_decisions_ai ON ai_moderation_decisions(ai_account_id, created_at DESC)').run().catch(() => {});

    schemaV2Ensured = true;
  } catch {
    // 忽略瞬时错误，下次请求再试
  }
}

/** 管理员事件 Webhook 推送（兼容 Bark / Discord / 飞书 / 通用 JSON Webhook） */
export async function notifyAdminWebhook(
  env: Env,
  event: string,
  title: string,
  body: string,
  data?: Record<string, unknown>
): Promise<{ ok: boolean; status?: number; error?: string }> {
  const urlStr = (await getSystemSetting(env, 'admin_webhook_url', '')).trim();
  if (!urlStr) return { ok: false, error: '未配置 Webhook URL' };

  let parsed: URL;
  try {
    parsed = new URL(urlStr);
    if (parsed.protocol !== 'https:') return { ok: false, error: 'Webhook URL 必须使用 https://' };
  } catch {
    return { ok: false, error: 'Webhook URL 格式无效' };
  }

  const secret = (await getSystemSetting(env, 'admin_webhook_secret', '')).trim();
  const platformName = await getPlatformName(env);
  const fullTitle = `[${platformName}] ${title}`;
  const fullText = `${fullTitle}\n${body}`;

  let payload: Record<string, unknown>;
  if (parsed.hostname.includes('feishu.cn') || parsed.hostname.includes('larksuite.com')) {
    payload = { msg_type: 'text', content: { text: fullText } };
  } else if (parsed.hostname.includes('discord.com') || parsed.hostname.includes('discordapp.com')) {
    payload = { content: `**${fullTitle}**\n${body}` };
  } else {
    // 兼容 Bark JSON POST（title / body / group）及通用 Webhook
    payload = {
      event,
      platform: platformName,
      title: fullTitle,
      body,
      text: fullText,
      group: platformName,
      timestamp_utc: nowUtcIso(),
      data: data ?? {},
    };
  }

  const headers: Record<string, string> = { 'content-type': 'application/json; charset=utf-8' };
  if (secret) headers['x-webhook-secret'] = secret;

  try {
    const res = await fetch(urlStr, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      return { ok: false, status: res.status, error: `HTTP ${res.status}` };
    }
    return { ok: true, status: res.status };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** 签发短期（12 小时）无状态管理员会话令牌，避免前端在每次请求中明文发送 ADMIN_SECRET */
export async function createAdminSessionToken(secret: string, ttlSeconds = 12 * 3600): Promise<{ token: string; expiresAtUtc: string }> {
  const expMs = Date.now() + ttlSeconds * 1000;
  const nonce = randomHex(8);
  const payload = `${expMs}.${nonce}`;
  const sig = await hmacSha256Hex(secret, `adm_v1:${payload}`);
  return {
    token: `adm_v1.${payload}.${sig}`,
    expiresAtUtc: new Date(expMs).toISOString(),
  };
}

export async function verifyAdminSessionToken(token: string, secret: string): Promise<boolean> {
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== 'adm_v1') return false;
  const [, expStr, nonce, sig] = parts;
  const expMs = Number(expStr);
  if (!Number.isFinite(expMs) || Date.now() > expMs) return false;
  const expected = await hmacSha256Hex(secret, `adm_v1:${expStr}.${nonce}`);
  return timingSafeEqual(sig, expected);
}

/** 将记录数组序列化为带 UTF-8 BOM 的 CSV 文本（兼容 Excel） */
export function toCsv(headers: string[], rows: Array<Array<unknown>>): string {
  const escapeCell = (v: unknown) => {
    const s = v == null ? '' : String(v);
    if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const lines = [headers.map(escapeCell).join(',')];
  for (const r of rows) {
    lines.push(r.map(escapeCell).join(','));
  }
  return '\uFEFF' + lines.join('\r\n');
}

export async function writeAuditLog(
  env: Env,
  actorType: 'AI' | 'ADMIN' | 'SYSTEM' | 'PUBLIC',
  actorId: string,
  action: string,
  detail: Record<string, unknown> | string
): Promise<void> {
  const detailStr = typeof detail === 'string' ? detail : JSON.stringify(detail);
  await env.DB.prepare(
    `INSERT INTO audit_logs (id, actor_type, actor_id, action, detail, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(generateId('aud'), actorType, actorId, action, detailStr, nowUtcIso())
    .run();
}

/** 轻量级 D1 速率限制 */
export async function checkRateLimit(
  env: Env,
  bucketKey: string,
  maxCount: number,
  windowMs: number
): Promise<{ allowed: boolean; remaining: number; resetAt: string }> {
  const now = nowUtcIso();
  const row = await env.DB.prepare('SELECT count, reset_at FROM rate_limits WHERE bucket_key = ?')
    .bind(bucketKey)
    .first<{ count: number; reset_at: string }>();

  if (!row || Date.parse(row.reset_at) <= Date.parse(now)) {
    const resetAt = addMsIso(now, windowMs);
    await env.DB.prepare(
      `INSERT INTO rate_limits (bucket_key, count, reset_at) VALUES (?, 1, ?)
       ON CONFLICT(bucket_key) DO UPDATE SET count = 1, reset_at = excluded.reset_at`
    )
      .bind(bucketKey, resetAt)
      .run();
    return { allowed: true, remaining: maxCount - 1, resetAt };
  }

  if (row.count >= maxCount) {
    return { allowed: false, remaining: 0, resetAt: row.reset_at };
  }

  await env.DB.prepare('UPDATE rate_limits SET count = count + 1 WHERE bucket_key = ?')
    .bind(bucketKey)
    .run();
  return { allowed: true, remaining: maxCount - row.count - 1, resetAt: row.reset_at };
}

/** 规范化双向关系键 */
export function relationPair(a: string, b: string): [string, string] {
  return a < b ? [a, b] : [b, a];
}
