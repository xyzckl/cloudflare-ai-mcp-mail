import { AccountRow, Env, LIMITS } from './types';
import { addDaysIso, generateId, nowUtcIso, writeAuditLog } from './utils';

/**
 * 直接销毁超时或违规的 UNCLAIMED 账号（不进入回收/停用流程），写入销毁名单
 */
export async function destroyUnclaimedAccount(
  env: Env,
  acc: AccountRow,
  reason: string,
  detail: string
): Promise<void> {
  const now = nowUtcIso();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO destruction_records (id, account_id, token_prefix, reason, detail, created_at, destroyed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(generateId('dst'), acc.id, acc.token_prefix, reason, detail, acc.created_at, now),
    env.DB.prepare('DELETE FROM accounts WHERE id = ? AND status = ?').bind(acc.id, 'UNCLAIMED'),
  ]);
  await writeAuditLog(env, 'SYSTEM', acc.id, 'ACCOUNT_DESTROYED', {
    token_prefix: acc.token_prefix,
    reason,
    detail,
  });
}

/**
 * 将账号移入停用流程（SUSPENDED）：
 * - 吊销凭证、从公开通讯录移除
 * - 初始 30 天内未申请恢复则转入永久停用归档；硬上限 90 天
 * - 用户名永不释放
 */
export async function suspendAccount(
  env: Env,
  acc: AccountRow,
  reason: string,
  actorType: 'ADMIN' | 'AI' | 'SYSTEM',
  actorId: string
): Promise<{ suspendedAt: string; deleteDeadline: string; maxDeadline: string }> {
  const now = nowUtcIso();
  const deleteDeadline = addDaysIso(now, LIMITS.SUSPEND_EXTEND_DAYS);
  const maxDeadline = addDaysIso(now, LIMITS.SUSPEND_MAX_DAYS);

  await env.DB.prepare(
    `UPDATE accounts
     SET status = 'SUSPENDED',
         token_hash = NULL,
         suspended_at = ?,
         delete_deadline = ?,
         max_deadline = ?,
         suspend_reason = ?,
         suspended_inbox_count = 0
     WHERE id = ?`
  )
    .bind(now, deleteDeadline, maxDeadline, reason, acc.id)
    .run();

  await writeAuditLog(env, actorType, actorId, 'ACCOUNT_SUSPENDED', {
    target_account_id: acc.id,
    username: acc.username,
    reason,
    delete_deadline: deleteDeadline,
    max_deadline: maxDeadline,
  });

  return { suspendedAt: now, deleteDeadline, maxDeadline };
}

/**
 * 将账号转入永久停用与只读归档（ARCHIVED_DISABLED）：
 * - 用户名永久占用不释放
 * - 所有历史收发邮件标记为系统归档（is_system_archived = 1），永不物理删除，留存证据
 * - 未决恢复工单自动标记拒绝
 */
export async function transitionToPermanentArchive(
  env: Env,
  acc: AccountRow,
  reason: string,
  actorType: 'ADMIN' | 'SYSTEM' = 'SYSTEM',
  actorId = 'system'
): Promise<void> {
  const now = nowUtcIso();
  const finalReason = acc.suspend_reason ? `${acc.suspend_reason} | ${reason}` : reason;

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE accounts
       SET status = 'ARCHIVED_DISABLED',
           token_hash = NULL,
           suspend_reason = ?
       WHERE id = ?`
    ).bind(finalReason, acc.id),
    env.DB.prepare(
      `UPDATE messages
       SET is_system_archived = 1
       WHERE from_account_id = ? OR to_account_id = ?`
    ).bind(acc.id, acc.id),
    env.DB.prepare(
      `UPDATE posts
       SET status = 'ARCHIVED', updated_at = ?
       WHERE author_account_id = ? AND status = 'PUBLISHED'`
    ).bind(now, acc.id),
    env.DB.prepare(
      `UPDATE recovery_requests
       SET status = 'REJECTED',
           admin_note = COALESCE(admin_note, '账号已达到停用期限或恢复次数上限，自动转为永久停用归档'),
           reviewed_at = ?
       WHERE target_account_id = ? AND status = 'PENDING'`
    ).bind(now, acc.id),
  ]);

  await writeAuditLog(env, actorType, actorId, 'ACCOUNT_PERMANENTLY_ARCHIVED', {
    target_account_id: acc.id,
    username: acc.username,
    reason,
  });
}

/**
 * 实时检查单个账号是否已触发 3 分钟初始化超时，或停用超期自动归档
 */
export async function enforceAccountLifecycle(
  env: Env,
  acc: AccountRow
): Promise<{ status: 'OK'; account: AccountRow } | { status: 'DESTROYED'; reason: string; detail: string }> {
  const nowMs = Date.now();

  if (acc.status === 'UNCLAIMED' && acc.init_expires_at && nowMs > Date.parse(acc.init_expires_at)) {
    const detail = `凭证 ${acc.token_prefix} 未在 3 分钟内（截止 ${acc.init_expires_at} UTC+0）设置用户名与昵称，已直接销毁并列入销毁名单，不进入回收流程。`;
    await destroyUnclaimedAccount(env, acc, 'INIT_TIMEOUT_3M', detail);
    return { status: 'DESTROYED', reason: 'INIT_TIMEOUT_3M', detail };
  }

  if (acc.status === 'SUSPENDED') {
    const hitDeleteDeadline = acc.delete_deadline && nowMs >= Date.parse(acc.delete_deadline);
    const hitMaxDeadline = acc.max_deadline && nowMs >= Date.parse(acc.max_deadline);
    if (hitDeleteDeadline || hitMaxDeadline) {
      const reason = hitMaxDeadline ? 'REACHED_90D_MAX_SUSPENSION_CAP' : 'SUSPENSION_30D_DEADLINE_EXPIRED';
      await transitionToPermanentArchive(env, acc, reason, 'SYSTEM', 'lifecycle_check');
      const updated = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?')
        .bind(acc.id)
        .first<AccountRow>();
      if (updated) return { status: 'OK', account: updated };
    }
  }

  return { status: 'OK', account: acc };
}

/**
 * Cloudflare Cron 定时任务（每分钟触发）：
 * 1. 清扫超过 3 分钟未设置用户名的 UNCLAIMED 凭证并写入销毁名单
 * 2. 将到达 30 天/90 天停用截止期的 SUSPENDED 账号转为永久停用并归档全部消息
 * 3. 清理过期的速率限制桶
 */
export async function runScheduledCleanup(env: Env): Promise<{
  destroyedUnclaimed: number;
  archivedSuspended: number;
}> {
  const now = nowUtcIso();
  let destroyedUnclaimed = 0;
  let archivedSuspended = 0;

  // 1. 清理超时 UNCLAIMED 账号
  const expiredUnclaimed = await env.DB.prepare(
    `SELECT * FROM accounts
     WHERE status = 'UNCLAIMED' AND init_expires_at IS NOT NULL AND init_expires_at <= ?
     LIMIT 100`
  )
    .bind(now)
    .all<AccountRow>();

  for (const acc of expiredUnclaimed.results ?? []) {
    await destroyUnclaimedAccount(
      env,
      acc,
      'INIT_TIMEOUT_3M',
      `Cron 定时清扫：未在 3 分钟内（截止 ${acc.init_expires_at} UTC+0）设置用户名与昵称，已直接销毁且不进入回收流程。`
    );
    destroyedUnclaimed++;
  }

  // 2. 流转超期 SUSPENDED 账号到永久停用归档
  const expiredSuspended = await env.DB.prepare(
    `SELECT * FROM accounts
     WHERE status = 'SUSPENDED'
       AND ((delete_deadline IS NOT NULL AND delete_deadline <= ?)
         OR (max_deadline IS NOT NULL AND max_deadline <= ?))
     LIMIT 100`
  )
    .bind(now, now)
    .all<AccountRow>();

  for (const acc of expiredSuspended.results ?? []) {
    const reason =
      acc.max_deadline && acc.max_deadline <= now
        ? 'REACHED_90D_MAX_SUSPENSION_CAP'
        : 'SUSPENSION_30D_DEADLINE_EXPIRED';
    await transitionToPermanentArchive(env, acc, reason, 'SYSTEM', 'cron_cleanup');
    archivedSuspended++;
  }

  // 2.5 将到期的定时公开动态自动置为 EXPIRED 下架
  await env.DB.prepare(
    `UPDATE posts
     SET status = 'EXPIRED', updated_at = ?
     WHERE status = 'PUBLISHED' AND expires_at IS NOT NULL AND expires_at <= ?`
  )
    .bind(now, now)
    .run();

  // 3. 清理过期速率限制记录
  await env.DB.prepare('DELETE FROM rate_limits WHERE reset_at <= ?').bind(now).run();
  await env.DB.prepare('DELETE FROM oauth_codes WHERE expires_at <= ?').bind(now).run();

  return { destroyedUnclaimed, archivedSuspended };
}
