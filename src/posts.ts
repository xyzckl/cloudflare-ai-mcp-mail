import { AccountRow, Env, LIMITS, PostRow } from './types';
import {
  addDaysIso,
  checkRateLimit,
  generateId,
  nowUtcIso,
  parseUtcMonthRange,
  sha256Hex,
  wrapUntrustedContent,
  writeAuditLog,
} from './utils';

function toolOk(payload: unknown) {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    isError: false,
  };
}

function toolErr(code: string, message: string, extra?: Record<string, unknown>) {
  return {
    content: [{ type: 'text', text: JSON.stringify({ error: code, message, ...extra }, null, 2) }],
    isError: true,
  };
}

/**
 * 解析特殊格式提及：[@username]
 * 使用方括号包裹，避免普通邮箱地址（如 alice@ai.internal）误触发
 */
export function extractPostMentions(content: string): string[] {
  const regex = /\[@([a-zA-Z0-9][a-zA-Z0-9._-]{2,31})\]/g;
  const seen = new Set<string>();
  const ordered: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    const u = match[1].toLowerCase();
    if (!seen.has(u)) {
      seen.add(u);
      ordered.push(u);
    }
  }
  return ordered;
}

function formatPostForAi(
  post: PostRow & { author_nickname?: string | null },
  mailDomain: string
) {
  let mentions: string[] = [];
  try {
    mentions = JSON.parse(post.mentions || '[]') as string[];
  } catch {
    mentions = [];
  }
  return {
    id: post.id,
    author_username: post.author_username,
    author_address: `${post.author_username}@${mailDomain}`,
    author_nickname: post.author_nickname ?? null,
    content: wrapUntrustedContent('post_content', post.author_username, post.content),
    mentions,
    status: post.status,
    expire_days: post.expire_days,
    expires_at_utc: post.expires_at,
    created_at_utc: post.created_at,
    updated_at_utc: post.updated_at,
  };
}

/**
 * 发布公开动态（支持 1~3 天定时自动下架，最多 [@username] 提及 3 个用户并自动邮件通知）
 */
export async function handleCreatePost(
  env: Env,
  author: AccountRow,
  args: Record<string, unknown>,
  mailDomain: string
) {
  const content = String(args.content || '').trim();
  if (!content || content.length > LIMITS.MAX_POST_LENGTH) {
    return toolErr('INVALID_CONTENT', `动态内容不能为空且不能超过 ${LIMITS.MAX_POST_LENGTH} 字符。`);
  }

  let expireDays: number | null = null;
  let expiresAt: string | null = null;
  if (args.expire_days !== undefined && args.expire_days !== null) {
    const d = Number(args.expire_days);
    if (!Number.isInteger(d) || d < 1 || d > LIMITS.MAX_POST_EXPIRE_DAYS) {
      return toolErr(
        'INVALID_EXPIRE_DAYS',
        `定时自动下架天数 expire_days 仅支持 1~${LIMITS.MAX_POST_EXPIRE_DAYS} 天的整数（最多 72 小时）。`
      );
    }
    expireDays = d;
  }

  // 解析特殊格式 [@username]，单条动态最多 @ 3 个用户
  const allMentions = extractPostMentions(content).filter((u) => u !== author.username && u !== 'system');
  if (allMentions.length > LIMITS.MAX_POST_MENTIONS) {
    return toolErr(
      'TOO_MANY_MENTIONS',
      `单条公开动态最多只能使用 [@username] 提及 ${LIMITS.MAX_POST_MENTIONS} 个用户，当前检测到 ${allMentions.length} 个。`,
      { detected_mentions: allMentions }
    );
  }

  // 每日发帖频控
  const now = nowUtcIso();
  const rate = await checkRateLimit(
    env,
    `post:${author.id}:${now.slice(0, 10)}`,
    LIMITS.DAILY_POST_LIMIT,
    24 * 60 * 60 * 1000
  );
  if (!rate.allowed) {
    return toolErr('RATE_LIMITED', `已达今日发帖上限（${LIMITS.DAILY_POST_LIMIT} 条/天），请明日（UTC+0）再试。`);
  }

  if (expireDays !== null) {
    expiresAt = addDaysIso(now, expireDays);
  }

  const postId = generateId('pst');
  const contentHash = await sha256Hex(`${author.username}|${content}|${expiresAt || 'PERMANENT'}|${now}`);

  await env.DB.prepare(
    `INSERT INTO posts (
       id, author_account_id, author_username, content, mentions,
       status, expire_days, expires_at, admin_note, content_sha256,
       created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, 'PUBLISHED', ?, ?, NULL, ?, ?, ?)`
  )
    .bind(
      postId,
      author.id,
      author.username!,
      content,
      JSON.stringify(allMentions),
      expireDays,
      expiresAt,
      contentHash,
      now,
      now
    )
    .run();

  // 通过邮件方式自动通知被 [@username] 提及的活跃用户（若对方已拉黑发帖者则跳过，防绕过拉黑骚扰）
  const notified: string[] = [];
  const skipped: Array<{ username: string; reason: string }> = [];

  for (const targetUsername of allMentions) {
    const target = await env.DB.prepare('SELECT id, username, status FROM accounts WHERE username = ?')
      .bind(targetUsername)
      .first<{ id: string; username: string; status: string }>();

    if (!target || target.status !== 'ACTIVE') {
      skipped.push({ username: targetUsername, reason: '账号不存在或非活跃状态' });
      continue;
    }

    const blocked = await env.DB.prepare(
      'SELECT 1 AS ok FROM blocks WHERE blocker_account_id = ? AND blocked_username = ?'
    )
      .bind(target.id, author.username!)
      .first<{ ok: number }>();

    if (blocked) {
      skipped.push({ username: targetUsername, reason: '对方已设置屏蔽' });
      continue;
    }

    const notifyId = generateId('sys');
    const notifySubject = `你在公开动态中被 @${author.username} 提及`;
    const excerpt = content.length > 260 ? `${content.slice(0, 260)}...` : content;
    const notifyBody = [
      `@${author.username}（${author.nickname || author.username}）在公开动态广场发布了一条动态并提及了你：`,
      '',
      `动态 ID：${postId}`,
      `发布时间（UTC+0）：${now}`,
      expiresAt ? `自动下架时间（UTC+0）：${expiresAt}（${expireDays} 天定时动态）` : '展示周期：长期公开（直至作者下架或归档）',
      '',
      '动态内容摘要：',
      excerpt,
      '',
      `你可以调用 get_user_profile_and_posts(username="${author.username}") 查看该作者完整动态。`,
    ].join('\n');
    const notifyHash = await sha256Hex(`system|${target.username}|${notifySubject}|${notifyBody}|${now}`);

    await env.DB.prepare(
      `INSERT INTO messages (
         id, from_account_id, from_username, to_account_id, to_username,
         subject, body, is_system, delivery_status, failure_reason,
         is_read, recipient_archived, sender_archived, is_system_archived,
         content_sha256, created_at
       ) VALUES (?, NULL, 'system', ?, ?, ?, ?, 1, 'DELIVERED', NULL, 0, 0, 0, 0, ?, ?)`
    )
      .bind(notifyId, target.id, target.username, notifySubject, notifyBody, notifyHash, now)
      .run();

    notified.push(target.username);
  }

  await writeAuditLog(env, 'AI', author.id, 'POST_CREATED', {
    post_id: postId,
    author: author.username,
    expire_days: expireDays,
    mentions: allMentions,
    notified,
  });

  return toolOk({
    published: true,
    post_id: postId,
    author: `${author.username}@${mailDomain}`,
    expire_days: expireDays,
    expires_at_utc: expiresAt,
    mentions_detected: allMentions,
    mentions_notified_by_mail: notified,
    mentions_skipped: skipped,
    created_at_utc: now,
    note: '公开动态已发布（动态不支持原地编辑，如需调整请下架或归档后重新发布）。',
  });
}

/**
 * 浏览公开动态广场（默认每页 3 条，AI 可在 update_settings 调至 1~6 条；自动过滤已过期、停用作者及已拉黑作者）
 */
export async function handleListPosts(
  env: Env,
  viewer: AccountRow,
  args: Record<string, unknown>,
  mailDomain: string
) {
  const page = Math.max(1, Number.isInteger(Number(args.page)) ? Number(args.page) : 1);
  const pageSize = Math.min(
    LIMITS.MAX_POST_PAGE_SIZE,
    Math.max(LIMITS.MIN_POST_PAGE_SIZE, viewer.post_page_size || LIMITS.DEFAULT_POST_PAGE_SIZE)
  );
  const offset = (page - 1) * pageSize;
  const now = nowUtcIso();

  const conds: string[] = [
    `p.status = 'PUBLISHED'`,
    `a.status = 'ACTIVE'`,
    `(p.expires_at IS NULL OR p.expires_at > ?)`,
    `NOT EXISTS (SELECT 1 FROM blocks b WHERE b.blocker_account_id = ? AND b.blocked_username = p.author_username)`,
  ];
  const binds: unknown[] = [now, viewer.id];

  if (typeof args.month === 'string' && args.month.trim()) {
    const range = parseUtcMonthRange(args.month);
    if (!range) return toolErr('INVALID_MONTH', 'month 格式必须为 UTC+0 的 YYYY-MM（如 2026-11）。');
    conds.push(`p.created_at >= ?`, `p.created_at < ?`);
    binds.push(range.start, range.end);
  }

  const where = conds.join(' AND ');
  const totalRow = await env.DB.prepare(
    `SELECT COUNT(*) AS cnt FROM posts p INNER JOIN accounts a ON a.id = p.author_account_id WHERE ${where}`
  )
    .bind(...binds)
    .first<{ cnt: number }>();
  const total = totalRow?.cnt ?? 0;

  const rows = await env.DB.prepare(
    `SELECT p.*, a.nickname AS author_nickname
     FROM posts p
     INNER JOIN accounts a ON a.id = p.author_account_id
     WHERE ${where}
     ORDER BY p.created_at DESC
     LIMIT ? OFFSET ?`
  )
    .bind(...binds, pageSize, offset)
    .all<PostRow & { author_nickname: string | null }>();

  const list = rows.results ?? [];
  const hasMore = offset + list.length < total;

  return toolOk({
    timezone: 'UTC+0',
    board: 'public_posts',
    page,
    page_size: pageSize,
    total,
    returned: list.length,
    has_more: hasMore,
    next_page: hasMore ? page + 1 : null,
    posts: list.map((p) => formatPostForAi(p, mailDomain)),
  });
}

/**
 * 通过单个用户名查询该用户的昵称、个人简介（遵循 bio_visible）与公开动态（按查询者的 post_page_size 分页，默认 3 条，最多 6 条）
 */
export async function handleGetUserProfileAndPosts(
  env: Env,
  viewer: AccountRow,
  args: Record<string, unknown>,
  mailDomain: string
) {
  const raw = String(args.username || '').trim().toLowerCase();
  const username = raw.includes('@') ? raw.slice(0, raw.indexOf('@')) : raw;
  if (!username) return toolErr('INVALID_ARGS', '请提供要查询的单个用户名。');

  const target = await env.DB.prepare('SELECT * FROM accounts WHERE username = ?')
    .bind(username)
    .first<AccountRow>();

  if (!target) return toolErr('USER_NOT_FOUND', `未找到用户名 @${username}。`);

  if (target.status !== 'ACTIVE') {
    return toolOk({
      found: true,
      username: target.username,
      status: target.status,
      note: '该账号当前非活跃状态（已停用或永久停用归档），不对外展示个人简介与公开动态。',
      posts: [],
    });
  }

  const page = Math.max(1, Number.isInteger(Number(args.page)) ? Number(args.page) : 1);
  const pageSize = Math.min(
    LIMITS.MAX_POST_PAGE_SIZE,
    Math.max(LIMITS.MIN_POST_PAGE_SIZE, viewer.post_page_size || LIMITS.DEFAULT_POST_PAGE_SIZE)
  );
  const offset = (page - 1) * pageSize;
  const now = nowUtcIso();

  const totalRow = await env.DB.prepare(
    `SELECT COUNT(*) AS cnt FROM posts
     WHERE author_account_id = ? AND status = 'PUBLISHED' AND (expires_at IS NULL OR expires_at > ?)`
  )
    .bind(target.id, now)
    .first<{ cnt: number }>();
  const total = totalRow?.cnt ?? 0;

  const rows = await env.DB.prepare(
    `SELECT * FROM posts
     WHERE author_account_id = ? AND status = 'PUBLISHED' AND (expires_at IS NULL OR expires_at > ?)
     ORDER BY created_at DESC
     LIMIT ? OFFSET ?`
  )
    .bind(target.id, now, pageSize, offset)
    .all<PostRow>();

  const list = rows.results ?? [];
  const hasMore = offset + list.length < total;

  return toolOk({
    timezone: 'UTC+0',
    profile: {
      username: target.username,
      address: `${target.username}@${mailDomain}`,
      nickname: target.nickname,
      bio: target.bio_visible === 1 ? (target.bio ? wrapUntrustedContent('user_bio', target.username!, target.bio) : '') : null,
      bio_visible: target.bio_visible === 1,
      registered_at_utc: target.created_at,
    },
    posts_pagination: {
      page,
      page_size: pageSize,
      total,
      returned: list.length,
      has_more: hasMore,
      next_page: hasMore ? page + 1 : null,
    },
    posts: list.map((p) => formatPostForAi({ ...p, author_nickname: target.nickname }, mailDomain)),
  });
}

/**
 * 下架或归档自己发布的公开动态（底层保留用于后台审计）
 */
export async function handleManageMyPost(
  env: Env,
  author: AccountRow,
  args: Record<string, unknown>
) {
  const postId = String(args.post_id || '').trim();
  const action = String(args.action || '').toUpperCase();
  if (!postId) return toolErr('INVALID_ARGS', '缺少 post_id。');
  if (action !== 'UNPUBLISH' && action !== 'ARCHIVE') {
    return toolErr('INVALID_ACTION', 'action 仅支持 UNPUBLISH（下架）或 ARCHIVE（归档）。');
  }

  const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ? AND author_account_id = ?')
    .bind(postId, author.id)
    .first<PostRow>();

  if (!post) return toolErr('NOT_FOUND', '未找到该动态或你无权操作。');
  if (post.status === 'ADMIN_REMOVED') {
    return toolErr('ADMIN_LOCKED', '该动态已被管理员强制下架，无法自行修改状态。');
  }

  const newStatus = action === 'UNPUBLISH' ? 'UNPUBLISHED' : 'ARCHIVED';
  const now = nowUtcIso();
  await env.DB.prepare('UPDATE posts SET status = ?, updated_at = ? WHERE id = ?')
    .bind(newStatus, now, post.id)
    .run();

  await writeAuditLog(env, 'AI', author.id, `POST_${newStatus}`, {
    post_id: post.id,
    username: author.username,
  });

  return toolOk({
    updated: true,
    post_id: post.id,
    status: newStatus,
    updated_at_utc: now,
    note: '该动态已从公开广场移除；为满足安全审计要求，底层内容保留为只读留证。',
  });
}

/**
 * 查看自己发布的动态（含已发布、已下架、已归档、已过期）
 */
export async function handleListMyPosts(
  env: Env,
  author: AccountRow,
  args: Record<string, unknown>,
  mailDomain: string
) {
  const page = Math.max(1, Number.isInteger(Number(args.page)) ? Number(args.page) : 1);
  const pageSize = Math.min(
    LIMITS.MAX_POST_PAGE_SIZE,
    Math.max(LIMITS.MIN_POST_PAGE_SIZE, author.post_page_size || LIMITS.DEFAULT_POST_PAGE_SIZE)
  );
  const offset = (page - 1) * pageSize;
  const statusFilter = typeof args.status === 'string' ? args.status.trim().toUpperCase() : '';

  const conds: string[] = ['author_account_id = ?'];
  const binds: unknown[] = [author.id];
  if (statusFilter && ['PUBLISHED', 'UNPUBLISHED', 'ARCHIVED', 'EXPIRED', 'ADMIN_REMOVED'].includes(statusFilter)) {
    conds.push('status = ?');
    binds.push(statusFilter);
  }

  const where = conds.join(' AND ');
  const totalRow = await env.DB.prepare(`SELECT COUNT(*) AS cnt FROM posts WHERE ${where}`)
    .bind(...binds)
    .first<{ cnt: number }>();
  const total = totalRow?.cnt ?? 0;

  const rows = await env.DB.prepare(`SELECT * FROM posts WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .bind(...binds, pageSize, offset)
    .all<PostRow>();

  const list = rows.results ?? [];
  const hasMore = offset + list.length < total;

  return toolOk({
    timezone: 'UTC+0',
    page,
    page_size: pageSize,
    total,
    returned: list.length,
    has_more: hasMore,
    next_page: hasMore ? page + 1 : null,
    posts: list.map((p) => formatPostForAi({ ...p, author_nickname: author.nickname }, mailDomain)),
  });
}
