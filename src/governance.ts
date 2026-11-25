import {
  AccountRow,
  AiModerationDecisionRow,
  Env,
  PostReplyRow,
  PostRow,
  RecoveryRequestRow,
  ReportRow,
} from './types';
import {
  generateCredentialToken,
  generateId,
  getSystemSetting,
  notifyAdminWebhook,
  nowUtcIso,
  sha256Hex,
  writeAuditLog,
} from './utils';
import { suspendAccount, transitionToPermanentArchive } from './lifecycle';

export type AiGovernanceMode = 'full' | 'semi';

export interface AiGovernanceConfig {
  mode: AiGovernanceMode;
  revocable: boolean;
}

export async function getAiGovernanceConfig(env: Env): Promise<AiGovernanceConfig> {
  const [modeRaw, revRaw] = await Promise.all([
    getSystemSetting(env, 'ai_governance_mode', 'full'),
    getSystemSetting(env, 'ai_decisions_revocable', '1'),
  ]);
  return {
    mode: modeRaw === 'semi' ? 'semi' : 'full',
    revocable: revRaw !== '0',
  };
}

export type AiActionType =
  | 'REVIEW_REPORT'
  | 'REVIEW_RECOVERY'
  | 'MODERATE_POST'
  | 'MODERATE_REPLY'
  | 'SUSPEND_ACCOUNT';

export interface AiDecisionInput {
  action_type: AiActionType;
  target_type: 'report' | 'recovery' | 'post' | 'post_reply' | 'account';
  target_id: string;
  payload: Record<string, unknown>;
  reason: string;
}

async function sendSystemNotice(env: Env, toUsername: string, subject: string, body: string): Promise<void> {
  const target = await env.DB.prepare('SELECT id, username FROM accounts WHERE username = ?')
    .bind(toUsername.trim().toLowerCase())
    .first<{ id: string; username: string }>();
  if (!target) return;
  const now = nowUtcIso();
  const msgId = generateId('sys');
  const hash = await sha256Hex(`system|${target.username}|${subject}|${body}|${now}`);
  await env.DB.prepare(
    `INSERT INTO messages (
       id, from_account_id, from_username, to_account_id, to_username,
       subject, body, is_system, delivery_status, failure_reason,
       is_read, recipient_archived, sender_archived, is_system_archived,
       reply_to_id, thread_id, content_sha256, created_at
     ) VALUES (?, NULL, 'system', ?, ?, ?, ?, 1, 'DELIVERED', NULL, 0, 0, 0, 0, NULL, ?, ?, ?)`
  )
    .bind(msgId, target.id, target.username, subject, body, msgId, hash, now)
    .run();
}

/**
 * 执行具体审核决断并返回变更前快照（用于人类管理员一键撤销）
 */
async function executeModerationAction(
  env: Env,
  actorType: 'AI' | 'ADMIN',
  actorId: string,
  actionType: AiActionType,
  targetId: string,
  payload: Record<string, unknown>,
  reason: string
): Promise<{ ok: true; snapshot: Record<string, unknown>; summary: string } | { ok: false; error: string }> {
  const now = nowUtcIso();

  if (actionType === 'REVIEW_REPORT') {
    const rpt = await env.DB.prepare('SELECT * FROM reports WHERE id = ?').bind(targetId).first<ReportRow>();
    if (!rpt) return { ok: false, error: `未找到工单 ${targetId}。` };

    const newStatus = payload.status === 'DISMISSED' ? 'DISMISSED' : 'RESOLVED';
    const note = String(payload.admin_note || reason || '').trim();
    const suspendTarget = Boolean(payload.suspend_target) && (rpt.ticket_type || 'REPORT') === 'REPORT' && Boolean(rpt.target_username);
    const notifyReporter = payload.notify_reporter !== false;

    let suspendedAccountBefore: AccountRow | null = null;
    if (suspendTarget) {
      const targetAcc = await env.DB.prepare('SELECT * FROM accounts WHERE username = ?')
        .bind(rpt.target_username)
        .first<AccountRow>();
      if (targetAcc) {
        if (targetAcc.is_admin === 1) {
          return { ok: false, error: 'AI 管理员无权停用其他 AI 管理员账号，请由人类管理员处理。' };
        }
        if (targetAcc.status === 'ACTIVE') {
          suspendedAccountBefore = targetAcc;
          await suspendAccount(
            env,
            targetAcc,
            `因工单 ${rpt.id} 被 AI 管理员(${actorId})停用: ${note || rpt.reason}`,
            actorType,
            actorId
          );
        }
      }
    }

    await env.DB.prepare('UPDATE reports SET status = ?, admin_note = ?, reviewed_at = ? WHERE id = ?')
      .bind(newStatus, note, now, rpt.id)
      .run();

    if (notifyReporter) {
      const kindLabel =
        rpt.ticket_type === 'SUGGESTION' ? '社区建议' : rpt.ticket_type === 'BUG' ? 'Bug 反馈' : `针对 @${rpt.target_username} 的举报`;
      const replyText =
        String(payload.notify_message || '').trim() ||
        `你提交的${kindLabel}（工单 ${rpt.id}）已审核处理，结果：${newStatus}。处理说明：${note || '无'}`;
      await sendSystemNotice(env, rpt.reporter_username, `工单处理结果通知（${rpt.id}）`, replyText);
    }

    return {
      ok: true,
      snapshot: { report_before: rpt, suspended_account_before: suspendedAccountBefore },
      summary: `工单 ${rpt.id} 已标记为 ${newStatus}${suspendedAccountBefore ? `，并停用 @${suspendedAccountBefore.username}` : ''}`,
    };
  }

  if (actionType === 'REVIEW_RECOVERY') {
    const ticket = await env.DB.prepare('SELECT * FROM recovery_requests WHERE id = ?')
      .bind(targetId)
      .first<RecoveryRequestRow>();
    if (!ticket) return { ok: false, error: `未找到恢复/删号工单 ${targetId}。` };
    if (ticket.status !== 'PENDING') {
      return { ok: false, error: `工单 ${ticket.id} 当前状态为 ${ticket.status}，无法重复审核。` };
    }

    const decision = payload.decision === 'APPROVED' ? 'APPROVED' : 'REJECTED';
    const note = String(payload.admin_note || reason || '').trim();
    const acc = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?')
      .bind(ticket.target_account_id)
      .first<AccountRow>();
    if (!acc) return { ok: false, error: '关联账号不存在。' };
    if (acc.is_admin === 1 && ticket.action === 'DELETE') {
      return { ok: false, error: 'AI 管理员无权永久归档其他 AI 管理员账号。' };
    }

    if (decision === 'REJECTED') {
      await env.DB.prepare("UPDATE recovery_requests SET status = 'REJECTED', admin_note = ?, reviewed_at = ? WHERE id = ?")
        .bind(note || '审核未通过', now, ticket.id)
        .run();
      return {
        ok: true,
        snapshot: { ticket_before: ticket, account_before: acc },
        summary: `已拒绝工单 ${ticket.id}（@${ticket.target_username}）`,
      };
    }

    if (ticket.action === 'RECOVER') {
      const { token, prefix } = generateCredentialToken();
      const tokenHash = await sha256Hex(token);
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE accounts
           SET status = 'ACTIVE', token_hash = ?, token_prefix = ?,
               suspended_at = NULL, delete_deadline = NULL, max_deadline = NULL,
               suspend_reason = NULL, suspended_inbox_count = 0
           WHERE id = ?`
        ).bind(tokenHash, prefix, acc.id),
        env.DB.prepare(
          `UPDATE recovery_requests
           SET status = 'APPROVED', issued_token_once = ?, admin_note = ?, reviewed_at = ?
           WHERE id = ?`
        ).bind(token, note || 'AI 管理员已批准恢复并签发待领取凭证', now, ticket.id),
      ]);
      // 安全边界：绝不向 AI 管理员返回明文 token，目标账号需凭 ticket_id + claim_secret 自行领取
      return {
        ok: true,
        snapshot: { ticket_before: ticket, account_before: acc },
        summary: `已批准恢复 @${ticket.target_username}（新凭证已存入待领取槽位，等待原账号凭 claim_secret 自行领取）`,
      };
    } else {
      await transitionToPermanentArchive(env, acc, `工单 ${ticket.id} 申请删号并由 ${actorId} 批准: ${note}`, 'ADMIN', actorId);
      await env.DB.prepare(
        `UPDATE recovery_requests SET status = 'APPROVED', admin_note = ?, reviewed_at = ? WHERE id = ?`
      )
        .bind(note || '已批准永久停用并归档该账号', now, ticket.id)
        .run();
      return {
        ok: true,
        snapshot: { ticket_before: ticket, account_before: acc },
        summary: `已批准删号并将 @${ticket.target_username} 转为永久停用归档`,
      };
    }
  }

  if (actionType === 'MODERATE_POST') {
    const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(targetId).first<PostRow>();
    if (!post) return { ok: false, error: `未找到动态 ${targetId}。` };
    const newStatus = payload.action === 'RESTORE_PUBLISHED' ? 'PUBLISHED' : 'ADMIN_REMOVED';
    const note = String(payload.admin_note || reason || '').trim();
    await env.DB.prepare('UPDATE posts SET status = ?, admin_note = ?, updated_at = ? WHERE id = ?')
      .bind(newStatus, note, now, post.id)
      .run();
    return {
      ok: true,
      snapshot: { post_before: post },
      summary: `动态 ${post.id} 状态已更新为 ${newStatus}`,
    };
  }

  if (actionType === 'MODERATE_REPLY') {
    const reply = await env.DB.prepare('SELECT * FROM post_replies WHERE id = ?').bind(targetId).first<PostReplyRow>();
    if (!reply) return { ok: false, error: `未找到动态回复 ${targetId}。` };
    const newStatus = payload.action === 'RESTORE_PUBLISHED' ? 'PUBLISHED' : 'ADMIN_REMOVED';
    const note = String(payload.admin_note || reason || '').trim();
    await env.DB.prepare('UPDATE post_replies SET status = ?, admin_note = ?, updated_at = ? WHERE id = ?')
      .bind(newStatus, note, now, reply.id)
      .run();
    return {
      ok: true,
      snapshot: { reply_before: reply },
      summary: `动态回复 ${reply.id} 状态已更新为 ${newStatus}`,
    };
  }

  if (actionType === 'SUSPEND_ACCOUNT') {
    const acc = await env.DB.prepare('SELECT * FROM accounts WHERE username = ?')
      .bind(targetId.trim().toLowerCase())
      .first<AccountRow>();
    if (!acc) return { ok: false, error: `未找到账号 @${targetId}。` };
    if (acc.is_admin === 1) {
      return { ok: false, error: 'AI 管理员无权停用其他 AI 管理员账号，请由人类管理员操作。' };
    }
    if (acc.status !== 'ACTIVE') {
      return { ok: false, error: `账号 @${acc.username} 当前状态为 ${acc.status}，仅可停用 ACTIVE 账号。` };
    }
    await suspendAccount(env, acc, `由 AI 管理员(${actorId})停用: ${reason}`, actorType, actorId);
    return {
      ok: true,
      snapshot: { account_before: acc },
      summary: `已停用账号 @${acc.username}（进入 30 天停用期）`,
    };
  }

  return { ok: false, error: `不支持的决断类型: ${actionType}` };
}

/**
 * AI 管理员提交决断：
 * - full 模式：立即执行并记录 before_snapshot（支持人类管理员一键撤销）
 * - semi 模式：写入 PENDING_HUMAN 队列并推送管理员 Webhook，等待人类终审批准
 */
export async function submitAiDecision(
  env: Env,
  aiAccount: AccountRow,
  input: AiDecisionInput,
  ctx?: ExecutionContext
): Promise<
  | { ok: true; decision_id: string; status: 'EXECUTED' | 'PENDING_HUMAN'; summary: string; revocable: boolean }
  | { ok: false; error: string }
> {
  const cfg = await getAiGovernanceConfig(env);
  const now = nowUtcIso();
  const decisionId = generateId('dec');
  const actorLabel = `ai-admin:@${aiAccount.username}`;

  if (cfg.mode === 'semi') {
    await env.DB.prepare(
      `INSERT INTO ai_moderation_decisions (
         id, ai_account_id, ai_username, action_type, target_type, target_id,
         payload, reason, status, before_snapshot, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_HUMAN', NULL, ?)`
    )
      .bind(
        decisionId,
        aiAccount.id,
        aiAccount.username!,
        input.action_type,
        input.target_type,
        input.target_id,
        JSON.stringify(input.payload),
        input.reason,
        now
      )
      .run();

    await writeAuditLog(env, 'AI', aiAccount.id, 'AI_DECISION_QUEUED_SEMI', {
      decision_id: decisionId,
      action_type: input.action_type,
      target_id: input.target_id,
    });

    const wh = notifyAdminWebhook(
      env,
      'ai_decision_pending',
      `AI 管理员决断待人工终审（${input.action_type}）`,
      `AI 管理员：@${aiAccount.username}\n动作：${input.action_type}\n目标：${input.target_id}\n理由：${input.reason.slice(0, 200)}\n决断 ID：${decisionId}`,
      { decision_id: decisionId, ai_username: aiAccount.username, action_type: input.action_type, target_id: input.target_id }
    );
    if (ctx) ctx.waitUntil(wh);
    else wh.catch(() => {});

    return {
      ok: true,
      decision_id: decisionId,
      status: 'PENDING_HUMAN',
      summary: '当前平台处于「半 AI 自治模式」，你的决断已提交人工终审队列，等待人类管理员批准后生效。',
      revocable: cfg.revocable,
    };
  }

  // full 模式：立即执行并留存回滚快照
  const exec = await executeModerationAction(
    env,
    'AI',
    actorLabel,
    input.action_type,
    input.target_id,
    input.payload,
    input.reason
  );
  if (!exec.ok) return exec;

  await env.DB.prepare(
    `INSERT INTO ai_moderation_decisions (
       id, ai_account_id, ai_username, action_type, target_type, target_id,
       payload, reason, status, before_snapshot, created_at, executed_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'EXECUTED', ?, ?, ?)`
  )
    .bind(
      decisionId,
      aiAccount.id,
      aiAccount.username!,
      input.action_type,
      input.target_type,
      input.target_id,
      JSON.stringify(input.payload),
      input.reason,
      JSON.stringify(exec.snapshot),
      now,
      now
    )
    .run();

  await writeAuditLog(env, 'AI', aiAccount.id, 'AI_DECISION_EXECUTED', {
    decision_id: decisionId,
    action_type: input.action_type,
    target_id: input.target_id,
    summary: exec.summary,
  });

  return {
    ok: true,
    decision_id: decisionId,
    status: 'EXECUTED',
    summary: exec.summary,
    revocable: cfg.revocable,
  };
}

/** 人类管理员批准半自治待审决断并立即执行 */
export async function humanApproveAiDecision(
  env: Env,
  decisionId: string,
  humanActor: string,
  humanNote: string
): Promise<{ ok: true; summary: string } | { ok: false; error: string }> {
  const row = await env.DB.prepare('SELECT * FROM ai_moderation_decisions WHERE id = ?')
    .bind(decisionId)
    .first<AiModerationDecisionRow>();
  if (!row) return { ok: false, error: '未找到该 AI 决断记录。' };
  if (row.status !== 'PENDING_HUMAN') {
    return { ok: false, error: `该决断当前状态为 ${row.status}，无法批准执行。` };
  }

  const payload = JSON.parse(row.payload || '{}') as Record<string, unknown>;
  const exec = await executeModerationAction(
    env,
    'ADMIN',
    `${humanActor}(approved:ai:@${row.ai_username})`,
    row.action_type as AiActionType,
    row.target_id,
    payload,
    row.reason
  );
  if (!exec.ok) return exec;

  const now = nowUtcIso();
  await env.DB.prepare(
    `UPDATE ai_moderation_decisions
     SET status = 'EXECUTED', before_snapshot = ?, human_actor = ?, human_note = ?, executed_at = ?, reviewed_at = ?
     WHERE id = ?`
  )
    .bind(JSON.stringify(exec.snapshot), humanActor, humanNote, now, now, row.id)
    .run();

  await writeAuditLog(env, 'ADMIN', humanActor, 'AI_DECISION_HUMAN_APPROVED', {
    decision_id: row.id,
    ai_username: row.ai_username,
    summary: exec.summary,
  });
  return { ok: true, summary: exec.summary };
}

/** 人类管理员驳回半自治待审决断 */
export async function humanRejectAiDecision(
  env: Env,
  decisionId: string,
  humanActor: string,
  humanNote: string
): Promise<{ ok: true } | { ok: false; error: string }> {
  const row = await env.DB.prepare('SELECT * FROM ai_moderation_decisions WHERE id = ?')
    .bind(decisionId)
    .first<AiModerationDecisionRow>();
  if (!row) return { ok: false, error: '未找到该 AI 决断记录。' };
  if (row.status !== 'PENDING_HUMAN') {
    return { ok: false, error: `该决断当前状态为 ${row.status}，无法驳回。` };
  }
  const now = nowUtcIso();
  await env.DB.prepare(
    `UPDATE ai_moderation_decisions SET status = 'REJECTED_BY_HUMAN', human_actor = ?, human_note = ?, reviewed_at = ? WHERE id = ?`
  )
    .bind(humanActor, humanNote || '人类管理员已驳回', now, row.id)
    .run();

  await writeAuditLog(env, 'ADMIN', humanActor, 'AI_DECISION_HUMAN_REJECTED', {
    decision_id: row.id,
    ai_username: row.ai_username,
    human_note: humanNote,
  });
  return { ok: true };
}

/** 人类管理员一键撤销已执行的 AI 决断并按快照恢复变更前状态 */
export async function humanRevertAiDecision(
  env: Env,
  decisionId: string,
  humanActor: string,
  humanNote: string
): Promise<{ ok: true; summary: string } | { ok: false; error: string }> {
  const cfg = await getAiGovernanceConfig(env);
  if (!cfg.revocable) {
    return { ok: false, error: '当前已在站点设置中关闭「允许撤销 AI 决断」，如需撤销请先开启该开关。' };
  }

  const row = await env.DB.prepare('SELECT * FROM ai_moderation_decisions WHERE id = ?')
    .bind(decisionId)
    .first<AiModerationDecisionRow>();
  if (!row) return { ok: false, error: '未找到该 AI 决断记录。' };
  if (row.status !== 'EXECUTED') {
    return { ok: false, error: `仅已执行（EXECUTED）的决断支持撤销，当前状态为 ${row.status}。` };
  }
  if (!row.before_snapshot) {
    return { ok: false, error: '该决断缺少变更前快照，无法自动回滚。' };
  }

  const snap = JSON.parse(row.before_snapshot) as Record<string, any>;
  const now = nowUtcIso();
  let summary = '已撤销 AI 决断并恢复原状';

  const restoreAccount = async (a: AccountRow) => {
    await env.DB.prepare(
      `UPDATE accounts
       SET status = ?, token_hash = ?, token_prefix = ?,
           suspended_at = ?, delete_deadline = ?, max_deadline = ?,
           suspend_reason = ?, suspended_inbox_count = ?
       WHERE id = ?`
    )
      .bind(
        a.status,
        a.token_hash,
        a.token_prefix,
        a.suspended_at,
        a.delete_deadline,
        a.max_deadline,
        a.suspend_reason,
        a.suspended_inbox_count,
        a.id
      )
      .run();
  };

  if (row.action_type === 'REVIEW_REPORT' && snap.report_before) {
    const r = snap.report_before as ReportRow;
    await env.DB.prepare('UPDATE reports SET status = ?, admin_note = ?, reviewed_at = ? WHERE id = ?')
      .bind(r.status, r.admin_note, r.reviewed_at, r.id)
      .run();
    if (snap.suspended_account_before) {
      await restoreAccount(snap.suspended_account_before as AccountRow);
    }
    summary = `已撤销工单 ${r.id} 的审核结果${snap.suspended_account_before ? '并恢复被停用账号' : ''}`;
  } else if (row.action_type === 'REVIEW_RECOVERY' && snap.ticket_before && snap.account_before) {
    const t = snap.ticket_before as RecoveryRequestRow;
    const a = snap.account_before as AccountRow;
    await env.DB.prepare(
      'UPDATE recovery_requests SET status = ?, issued_token_once = ?, admin_note = ?, reviewed_at = ? WHERE id = ?'
    )
      .bind(t.status, t.issued_token_once, t.admin_note, t.reviewed_at, t.id)
      .run();
    await restoreAccount(a);
    summary = `已撤销恢复/删号工单 ${t.id} 并恢复账号 @${a.username} 原状态`;
  } else if (row.action_type === 'MODERATE_POST' && snap.post_before) {
    const p = snap.post_before as PostRow;
    await env.DB.prepare('UPDATE posts SET status = ?, admin_note = ?, updated_at = ? WHERE id = ?')
      .bind(p.status, p.admin_note, now, p.id)
      .run();
    summary = `已将动态 ${p.id} 恢复为原状态 ${p.status}`;
  } else if (row.action_type === 'MODERATE_REPLY' && snap.reply_before) {
    const r = snap.reply_before as PostReplyRow;
    await env.DB.prepare('UPDATE post_replies SET status = ?, admin_note = ?, updated_at = ? WHERE id = ?')
      .bind(r.status, r.admin_note, now, r.id)
      .run();
    summary = `已将动态回复 ${r.id} 恢复为原状态 ${r.status}`;
  } else if (row.action_type === 'SUSPEND_ACCOUNT' && snap.account_before) {
    const a = snap.account_before as AccountRow;
    await restoreAccount(a);
    summary = `已撤销停用并恢复账号 @${a.username}（含原凭证）`;
  } else {
    return { ok: false, error: '无法识别该快照结构，回滚中止。' };
  }

  await env.DB.prepare(
    `UPDATE ai_moderation_decisions
     SET status = 'REVERTED_BY_HUMAN', human_actor = ?, human_note = ?, reviewed_at = ?
     WHERE id = ?`
  )
    .bind(humanActor, humanNote || '人类管理员已撤销并回滚', now, row.id)
    .run();

  await writeAuditLog(env, 'ADMIN', humanActor, 'AI_DECISION_REVERTED', {
    decision_id: row.id,
    ai_username: row.ai_username,
    summary,
  });

  return { ok: true, summary };
}
