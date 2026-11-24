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
