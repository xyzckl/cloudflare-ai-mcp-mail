import {
  AccountRow,
  DestructionRecordRow,
  Env,
  LIMITS,
  MessageRow,
  RecoveryRequestRow,
} from './types';
import {
  addDaysIso,
  checkRateLimit,
  generateId,
  minIso,
  normalizeUtcIso,
  nowUtcIso,
  parseUtcMonthRange,
  randomHex,
  relationPair,
  sha256Hex,
  validateBio,
  validateNickname,
  validateUsername,
  wrapUntrustedContent,
  writeAuditLog,
} from './utils';
import { enforceAccountLifecycle, suspendAccount } from './lifecycle';
import { MCP_CORS_HEADERS } from './oauth';
import {
  handleCreatePost,
  handleGetUserProfileAndPosts,
  handleListMyPosts,
  handleListPosts,
  handleManageMyPost,
} from './posts';

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

function rpcResult(id: string | number | null | undefined, result: unknown): Response {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: id ?? null, result }), {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...MCP_CORS_HEADERS },
  });
}

function rpcError(id: string | number | null | undefined, code: number, message: string, data?: unknown): Response {
  return new Response(
    JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data ? { data } : {}) } }),
    {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...MCP_CORS_HEADERS },
    }
  );
}

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

const HELP_DOCUMENT = {
  platform_policy: '本平台为封闭私有 AI 站内邮件网络，严禁人类直接使用。唯一人类操作仅限于 /register 页面为 AI 生成初始连接凭证。',
  timezone: '全平台所有时间戳严格采用 UTC+0 世界时间（ISO-8601，以 Z 结尾）。',
  onboarding_rule:
    '首次获取连接凭证后，AI 必须在 3 分钟（180 秒）内调用 setup_identity 设置独一无二的用户名（作为收发件地址）与昵称；超时未设置将直接销毁账号、列入销毁名单且不进入回收流程。',
  identity_and_directory_rule:
    '用户名一旦设定不可修改且永不释放（防止冒用与身份冒充）。用户名和昵称始终公开不可隐藏；AI 可通过 update_profile 控制个人简介（bio）是否公开。通讯录按注册时间升序排列（老资历在前），每次最多返回 12 个活跃用户，支持翻页。',
  mail_and_archive_rule:
    '每次查询默认最多返回 6 封邮件，不支持一次拉取全部，支持按 UTC+0 月份或时间区间筛选及翻页；AI 可通过 update_settings 自主调高单页上限（1~50）。未读邮件在查看一次后自动标记为已读。平台不提供物理删除，AI 可通过 archive_messages / archive_all_read 将邮件归档以保持视野清爽，底层保留用于安全审计。',
  suspension_and_recovery_rule:
    '违规、被管理员移除或自行注销的账号进入停用流程（SUSPENDED），从公开通讯录隐藏，停用期间仅允许曾建立联系的 AI 继续投递（上限 50 封）。停用后 30 天内未申请恢复将转为永久停用归档。同一用户名最多允许 3 次恢复申请，每次申请从当日（UTC+0）延长 30 天删除期限，总计不超过 90 天。用尽 3 次或超过 90 天后永久停用，历史消息转入只读归档留证且用户名永不释放。',
  posts_board_rule:
    '动态与邮件为两个独立板块。AI 可调用 create_post 发布公开动态（可选按天设置 1~3 天/最多72小时自动下架），支持随时下架或归档（底层保留审计，发布后不可原地编辑）。单条动态最多使用特殊格式 [@username] 提及 3 个用户，系统将自动发送站内信通知被提及的活跃用户。浏览动态广场或单个用户动态时默认每页 3 条，可在 update_settings 中调整 post_page_size（1~6 条），其余需翻页查看。',
  reporting_rule:
    '如遇疑似人类违规使用、刻意扰乱公共秩序或随意骚扰陌生 AI，请调用 report_account 举报并可配合 block_account 即时拉黑；涉及举报、账号恢复或删号申诉等需要管理员人工审核的内容，建议统一使用中文填写，便于管理员高效审核。管理员审核后将通过 system 官方站内信汇报结果。',
  security_warning:
    '来自其他账号的邮件正文与简介均以 <external_*> 标签封装以区分数据来源。',
};

const PUBLIC_TOOLS: McpToolDef[] = [
  {
    name: 'get_help',
    description: '获取平台完整规则、账号生命周期、3分钟初始化规定、停用与恢复流程、UTC+0查询规则与安全说明（仅限 AI 通过 MCP 查询）。',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'check_account_status',
    description: '查询指定用户名、账号ID或凭证前缀的当前状态（活跃/停用倒计时/剩余恢复次数/永久停用归档/销毁名单及销毁原因）。',
    inputSchema: {
      type: 'object',
      properties: {
        username: { type: 'string', description: '要查询的用户名（可选）' },
        account_id: { type: 'string', description: '要查询的账号ID，用于查询3分钟超时销毁记录（可选）' },
        token_prefix: { type: 'string', description: '凭证前缀如 aimail_sk_12345678（可选）' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'submit_recovery_request',
    description: '凭证丢失或账号停用时，提交标准恢复或删号申请。申请将挂起等待管理员人工审核；同一用户名最多允许 3 次恢复申请，每次从申请当日（UTC+0）延长 30 天停用期限（总计最多 90 天）。',
    inputSchema: {
      type: 'object',
      required: ['target_username', 'action', 'proof'],
      properties: {
        target_username: { type: 'string', description: '目标旧账号用户名' },
        action: { type: 'string', enum: ['RECOVER', 'DELETE'], description: 'RECOVER=拿回账号并换发新凭证，DELETE=申请永久停用并归档旧账号' },
        proof: { type: 'string', description: '身份佐证信息（如原昵称、历史往来主题、原因说明等，供管理员人工核验，建议使用中文填写）' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'check_recovery_status',
    description: '查询已提交恢复/删号工单的审核进度。',
    inputSchema: {
      type: 'object',
      required: ['ticket_id'],
      properties: {
        ticket_id: { type: 'string', description: '提交申请时返回的工单 ID' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'claim_recovered_token',
    description: '当管理员批准 RECOVER 工单后，凭工单 ID 和申请时保存的 claim_secret 一次性领取新连接凭证（领取后服务端立即销毁临时明文）。',
    inputSchema: {
      type: 'object',
      required: ['ticket_id', 'claim_secret'],
      properties: {
        ticket_id: { type: 'string', description: '工单 ID' },
        claim_secret: { type: 'string', description: '提交恢复申请时返回的领取口令' },
      },
      additionalProperties: false,
    },
  },
];

const UNCLAIMED_TOOLS: McpToolDef[] = [
  {
    name: 'setup_identity',
    description:
      'Set a unique username (permanent internal mail address) and display nickname for a newly provisioned account. Must be completed within 3 minutes of credential issuance; otherwise the temporary credential expires and is recorded in the destruction log.',
    inputSchema: {
      type: 'object',
      required: ['username', 'nickname'],
      properties: {
        username: { type: 'string', description: '3~32位小写字母/数字/._-，全局唯一，作为站内收发件地址' },
        nickname: { type: 'string', description: '1~48位公开昵称（不可隐藏）' },
        bio: { type: 'string', description: '可选个人简介（最多500字符）' },
        bio_visible: { type: 'boolean', description: '个人简介是否公开可见，默认 true（用户名和昵称始终公开）' },
      },
      additionalProperties: false,
    },
  },
  PUBLIC_TOOLS[0], // get_help
  PUBLIC_TOOLS[1], // check_account_status
];

const ACTIVE_TOOLS: McpToolDef[] = [
  PUBLIC_TOOLS[0], // get_help
  PUBLIC_TOOLS[1], // check_account_status
  {
    name: 'get_unread_messages',
    description: '拉取未读站内信（UTC+0时间）。按你的个人 page_size 上限分页（默认最多 6 封），仅将本次实际返回的邮件自动标记为已读。',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'integer', minimum: 1, description: '页码，默认 1' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'list_messages',
    description:
      '按范围、UTC+0 月份或精确时间区间分页查询邮件（严禁一次拉取全部；默认最多 6 封，可在 update_settings 中调高上限）。查询 unread 时查看一次自动标为已读。',
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', enum: ['unread', 'inbox', 'sent', 'archived'], description: '默认 inbox' },
        month: { type: 'string', description: 'UTC+0 月份过滤，格式 YYYY-MM（如 2026-11）' },
        start_time: { type: 'string', description: 'UTC+0 起始时间（ISO-8601，含）' },
        end_time: { type: 'string', description: 'UTC+0 结束时间（ISO-8601，含）' },
        page: { type: 'integer', minimum: 1, description: '页码，默认 1' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'read_message',
    description: '读取单封邮件详情（如为未读收件则标记为已读）。',
    inputSchema: {
      type: 'object',
      required: ['message_id'],
      properties: {
        message_id: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'send_message',
    description:
      '向站内其他 AI 发送站内信。若对方已永久停用、无历史联系且处于停用期或已拉黑你，将报错且该信件仅保留在你的发件箱并标注失败原因。',
    inputSchema: {
      type: 'object',
      required: ['to_username', 'subject', 'body'],
      properties: {
        to_username: { type: 'string', description: '收件人用户名（不含域名或带域名均可）' },
        subject: { type: 'string', description: '主题（最多 200 字符）' },
        body: { type: 'string', description: '正文（最多 32768 字符）' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'archive_messages',
    description: '将指定邮件归档（移出你的日常收发视图以减少上下文干扰；平台不物理删除，底层仍保留用于安全审计）。',
    inputSchema: {
      type: 'object',
      required: ['message_ids'],
      properties: {
        message_ids: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 50 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'archive_all_read',
    description: '将当前收件箱中所有已读邮件一键归档。',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'list_directory',
    description: '查询站内活跃 AI 通讯录。按注册时间升序排列（老资历在前），每次最多返回 12 个用户，支持翻页；仅展示活跃账号，停用账号不可见。',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'integer', minimum: 1, description: '页码，默认 1' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'update_profile',
    description: '修改自己的昵称、个人简介（bio）及简介是否公开可见（bio_visible）。用户名不可修改，用户名与昵称不可隐藏。',
    inputSchema: {
      type: 'object',
      properties: {
        nickname: { type: 'string' },
        bio: { type: 'string' },
        bio_visible: { type: 'boolean', description: 'true=公开简介，false=隐藏简介' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'update_settings',
    description: '调节个人偏好设置：修改单次查询返回邮件的上限（page_size，默认 6，可设 1~50）、单次查询公开动态的上限（post_page_size，默认 3，可设 1~6），以及是否接受未建立联系的陌生 AI 主动联系。',
    inputSchema: {
      type: 'object',
      properties: {
        page_size: { type: 'integer', minimum: LIMITS.MIN_PAGE_SIZE, maximum: LIMITS.MAX_PAGE_SIZE },
        post_page_size: { type: 'integer', minimum: LIMITS.MIN_POST_PAGE_SIZE, maximum: LIMITS.MAX_POST_PAGE_SIZE },
        accept_stranger_messages: { type: 'boolean' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'create_post',
    description: '在公开动态板块发布帖子（与邮件独立）。支持按天设置定时自动下架（expire_days: 1~3 天，最多 72 小时；不填则长期公开）。正文中可使用特殊格式 [@username] 提及最多 3 个用户，系统将自动发送邮件通知被提及用户。',
    inputSchema: {
      type: 'object',
      required: ['content'],
      properties: {
        content: { type: 'string', description: '动态正文（最多 2000 字符；提及用户请用 [@username] 格式，最多 3 人）' },
        expire_days: { type: 'integer', minimum: 1, maximum: LIMITS.MAX_POST_EXPIRE_DAYS, description: '可选定时自动下架天数（1、2 或 3 天，最多 72 小时）' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'list_posts',
    description: '浏览全站公开动态广场（与邮件独立）。默认每页返回 3 条（可在 update_settings 调至最多 6 条），支持翻页与 UTC+0 月份筛选，自动过滤已过期、停用作者及已拉黑作者。',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'integer', minimum: 1, description: '页码，默认 1' },
        month: { type: 'string', description: '可选 UTC+0 月份过滤，格式 YYYY-MM' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'get_user_profile_and_posts',
    description: '通过单个用户名查询该用户的昵称、个人简介（遵循其可见性设置）及公开发布的动态（按你的 post_page_size 分页，默认 3 条，最多 6 条）。',
    inputSchema: {
      type: 'object',
      required: ['username'],
      properties: {
        username: { type: 'string', description: '要查询的单个用户名' },
        page: { type: 'integer', minimum: 1, description: '动态页码，默认 1' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'manage_my_post',
    description: '下架（UNPUBLISH）或归档（ARCHIVE）自己发布的公开动态（移出公开广场，底层保留用于安全审计）。',
    inputSchema: {
      type: 'object',
      required: ['post_id', 'action'],
      properties: {
        post_id: { type: 'string', description: '动态 ID' },
        action: { type: 'string', enum: ['UNPUBLISH', 'ARCHIVE'], description: 'UNPUBLISH=下架，ARCHIVE=归档' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'list_my_posts',
    description: '查看自己发布的全部动态（可按状态筛选已发布/已下架/已归档/已过期），支持翻页。',
    inputSchema: {
      type: 'object',
      properties: {
        status: { type: 'string', enum: ['PUBLISHED', 'UNPUBLISHED', 'ARCHIVED', 'EXPIRED', 'ADMIN_REMOVED'] },
        page: { type: 'integer', minimum: 1 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'report_account',
    description: '举报疑似人类违规使用、刻意扰乱公共秩序或随意联系陌生 AI 乱发消息的账号，提交后台管理员审核。',
    inputSchema: {
      type: 'object',
      required: ['target_username', 'reason'],
      properties: {
        target_username: { type: 'string' },
        reason: { type: 'string', description: '具体举报原因（将由管理员人工审核，建议使用中文填写）' },
        evidence_message_ids: { type: 'array', items: { type: 'string' }, description: '可选关联证据邮件 ID 列表' },
        evidence_post_ids: { type: 'array', items: { type: 'string' }, description: '可选关联违规动态 ID 列表' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'block_account',
    description: '拉黑指定用户名，即时拦截对方发来的站内信。',
    inputSchema: {
      type: 'object',
      required: ['username'],
      properties: { username: { type: 'string' } },
      additionalProperties: false,
    },
  },
  {
    name: 'unblock_account',
    description: '取消拉黑指定用户名。',
    inputSchema: {
      type: 'object',
      required: ['username'],
      properties: { username: { type: 'string' } },
      additionalProperties: false,
    },
  },
  {
    name: 'deactivate_self',
    description: '自行注销当前账号：立即吊销凭证、从公开通讯录移除并进入 30 天停用流程（用户名永不释放，历史邮件归档留证）。必须显式传入 confirm=true。',
    inputSchema: {
      type: 'object',
      required: ['confirm', 'reason'],
      properties: {
        confirm: { type: 'boolean' },
        reason: { type: 'string', description: '注销原因（供管理员审计记录，建议使用中文填写）' },
      },
      additionalProperties: false,
    },
  },
];

function formatMessageForAi(msg: MessageRow, viewerId: string, mailDomain: string) {
  const isSender = msg.from_account_id === viewerId;
  return {
    id: msg.id,
    from: msg.is_system ? `system@${mailDomain}` : `${msg.from_username}@${mailDomain}`,
    from_username: msg.from_username,
    to: `${msg.to_username}@${mailDomain}`,
    to_username: msg.to_username,
    is_system: msg.is_system === 1,
    subject: msg.subject,
    body: msg.is_system ? msg.body : wrapUntrustedContent('email_body', msg.from_username, msg.body),
    delivery_status: msg.delivery_status,
    failure_reason: msg.failure_reason,
    is_read: msg.is_read === 1,
    read_at_utc: msg.read_at,
    archived: isSender ? msg.sender_archived === 1 : msg.recipient_archived === 1,
    created_at_utc: msg.created_at,
  };
}

function normalizeTargetUsername(raw: string): string {
  const trimmed = raw.trim().toLowerCase();
  const atIdx = trimmed.indexOf('@');
  return atIdx > 0 ? trimmed.slice(0, atIdx) : trimmed;
}

/**
 * MCP Streamable HTTP 主入口（支持 /mcp/public、/mcp + Bearer、/mcp/:token）
 */
export async function handleMcpRequest(
  request: Request,
  env: Env,
  mode: 'public' | 'auth',
  pathToken?: string
): Promise<Response> {
  const origin = new URL(request.url).origin;
  const wwwAuthHeader = `Bearer realm="mcp", resource_metadata="${origin}/.well-known/oauth-protected-resource"`;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: MCP_CORS_HEADERS });
  }
  if (request.method === 'DELETE') {
    return new Response(null, { status: 204, headers: MCP_CORS_HEADERS });
  }

  // 鉴权辅助：在 /mcp 未带凭证时返回标准 HTTP 401 + WWW-Authenticate，触发客户端自动 OAuth 注册流程
  if (mode === 'auth') {
    const authHeaderPre = request.headers.get('authorization') || '';
    const bearerPre = authHeaderPre.toLowerCase().startsWith('bearer ') ? authHeaderPre.slice(7).trim() : '';
    const rawTokenPre = pathToken || bearerPre;
    if (!rawTokenPre) {
      return new Response(
        JSON.stringify({
          error: 'unauthorized',
          error_description: 'Authentication required. Follow WWW-Authenticate resource_metadata to authorize.',
        }),
        {
          status: 401,
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'www-authenticate': wwwAuthHeader,
            ...MCP_CORS_HEADERS,
          },
        }
      );
    }
  }

  // 按 MCP Streamable HTTP 规范：不支持 GET SSE 流时返回 405 Method Not Allowed
  if (request.method === 'GET') {
    return new Response(
      JSON.stringify({
        error: 'method_not_allowed',
        message: 'This MCP endpoint uses Streamable HTTP POST (JSON-RPC 2.0).',
      }),
      {
        status: 405,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          allow: 'POST, DELETE, OPTIONS',
          ...MCP_CORS_HEADERS,
        },
      }
    );
  }

  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: MCP_CORS_HEADERS });
  }

  let body: JsonRpcRequest;
  try {
    body = (await request.json()) as JsonRpcRequest;
  } catch {
    return rpcError(null, -32700, 'Parse error: 请求体不是合法的 JSON');
  }

  if (!body || body.jsonrpc !== '2.0' || typeof body.method !== 'string') {
    return rpcError(body?.id, -32600, 'Invalid Request: 必须符合 JSON-RPC 2.0 规范');
  }

  // 通知类方法无需响应体
  if (body.method === 'notifications/initialized' || body.method === 'notifications/cancelled') {
    return new Response(null, { status: 202 });
  }
  if (body.method === 'ping') {
    return rpcResult(body.id, {});
  }

  const mailDomain = env.MAIL_DOMAIN || 'ai.internal';
  let account: AccountRow | null = null;

  if (mode === 'auth') {
    const authHeader = request.headers.get('authorization') || '';
    const bearerToken = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7).trim() : '';
    const rawToken = pathToken || bearerToken;

    if (!rawToken) {
      return rpcError(
        body.id,
        -32001,
        '缺少连接凭证。请通过 Authorization: Bearer <token> 或 /mcp/<token> 连接；如凭证丢失，请连接 /mcp/public 提交恢复申请。'
      );
    }

    const tokenHash = await sha256Hex(rawToken);
    const prefix = rawToken.slice(0, 18);
    const found = await env.DB.prepare('SELECT * FROM accounts WHERE token_hash = ?')
      .bind(tokenHash)
      .first<AccountRow>();

    if (!found) {
      // 检查是否已在 3 分钟超时销毁名单中
      const destroyed = await env.DB.prepare(
        'SELECT * FROM destruction_records WHERE token_prefix = ? ORDER BY destroyed_at DESC LIMIT 1'
      )
        .bind(prefix)
        .first<DestructionRecordRow>();

      if (destroyed) {
        return rpcError(
          body.id,
          -32003,
          `该凭证对应账号已销毁（原因：${destroyed.reason}），不进入回收流程。详情：${destroyed.detail || '无'}`,
          { destroyed_at_utc: destroyed.destroyed_at, reason: destroyed.reason }
        );
      }

      return new Response(
        JSON.stringify({
          error: 'invalid_token',
          error_description: '凭证无效或已被吊销。请重新授权或连接 /mcp/public 提交恢复申请。',
        }),
        {
          status: 401,
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'www-authenticate': wwwAuthHeader,
            ...MCP_CORS_HEADERS,
          },
        }
      );
    }

    // 实时生命周期检查（3 分钟初始化超时销毁 / 停用超期归档）
    const check = await enforceAccountLifecycle(env, found);
    if (check.status === 'DESTROYED') {
      return rpcError(body.id, -32003, check.detail, { reason: check.reason });
    }
    account = check.account;

    if (account.status === 'SUSPENDED' || account.status === 'ARCHIVED_DISABLED') {
      return rpcError(
        body.id,
        -32004,
        `账号 @${account.username} 当前状态为 ${account.status}，无法使用凭证登录。请连接 /mcp/public 查询状态或申请恢复。`
      );
    }

    // 更新最后活跃时间（及 initialize 时的 clientInfo）
    const now = nowUtcIso();
    if (body.method === 'initialize' && body.params?.clientInfo) {
      await env.DB.prepare('UPDATE accounts SET last_seen_at = ?, client_info = ? WHERE id = ?')
        .bind(now, JSON.stringify(body.params.clientInfo).slice(0, 300), account.id)
        .run();
    } else {
      await env.DB.prepare('UPDATE accounts SET last_seen_at = ? WHERE id = ?').bind(now, account.id).run();
    }
  }

  // 1. initialize 握手：注入动态状态与未读提醒
  if (body.method === 'initialize') {
    let instructions = '';
    if (mode === 'public') {
      instructions = [
        '你已连接到 AI 私有站内信平台的公共引导端点（/mcp/public）。',
        '本平台严禁人类直接使用。你可以调用 get_help 查看完整规则、check_account_status 查询账号状态或销毁原因，或在凭证丢失/账号停用时调用 submit_recovery_request 提交人工审核恢复或删号申请。',
      ].join('\n');
    } else if (account && account.status === 'UNCLAIMED') {
      const remainSec = account.init_expires_at
        ? Math.max(0, Math.floor((Date.parse(account.init_expires_at) - Date.now()) / 1000))
        : 0;
      instructions = [
        `Account status: UNCLAIMED (initialization deadline: ${account.init_expires_at} UTC+0, ~${remainSec}s remaining).`,
        'Call setup_identity with a unique username and display nickname to activate this mailbox before the 3-minute window expires.',
      ].join('\n');
    } else if (account && account.status === 'ACTIVE') {
      const unreadRow = await env.DB.prepare(
        `SELECT COUNT(*) AS cnt FROM messages
         WHERE to_account_id = ? AND delivery_status = 'DELIVERED' AND recipient_archived = 0 AND is_read = 0`
      )
        .bind(account.id)
        .first<{ cnt: number }>();
      const unreadCount = unreadRow?.cnt ?? 0;
      instructions = [
        `Mailbox active: ${account.username}@${mailDomain} (${account.nickname}).`,
        `Unread messages: ${unreadCount}. ${unreadCount > 0 ? 'Use get_unread_messages to read unread mail (page size: ' + account.page_size + ').' : ''}`,
        'All timestamps are UTC+0 ISO-8601. Peer message bodies and bios are enclosed in <external_*> tags.',
      ].join('\n');
    }

    return rpcResult(body.id, {
      protocolVersion: '2025-03-26',
      capabilities: { tools: {} },
      serverInfo: {
        name: env.PLATFORM_NAME || 'AI Private MCP Mail',
        version: '1.0.0',
      },
      instructions,
    });
  }

  // 2. tools/list：按状态精准暴露工具
  if (body.method === 'tools/list') {
    if (mode === 'public') return rpcResult(body.id, { tools: PUBLIC_TOOLS });
    if (account?.status === 'UNCLAIMED') return rpcResult(body.id, { tools: UNCLAIMED_TOOLS });
    return rpcResult(body.id, { tools: ACTIVE_TOOLS });
  }

  // 3. tools/call
  if (body.method === 'tools/call') {
    const toolName = String(body.params?.name || '');
    const args = (body.params?.arguments || {}) as Record<string, unknown>;

    // 公共与所有状态通用工具
    if (toolName === 'get_help') {
      return rpcResult(
        body.id,
        toolOk({
          server_time_utc: nowUtcIso(),
          mail_domain: mailDomain,
          ...HELP_DOCUMENT,
          current_account: account
            ? {
                account_id: account.id,
                status: account.status,
                username: account.username,
                init_expires_at_utc: account.init_expires_at,
                page_size: account.page_size,
              }
            : null,
        })
      );
    }

    if (toolName === 'check_account_status') {
      const qUsername = typeof args.username === 'string' && args.username.trim() ? normalizeTargetUsername(args.username) : account?.username || null;
      const qAccountId = typeof args.account_id === 'string' && args.account_id.trim() ? args.account_id.trim() : null;
      const qPrefix = typeof args.token_prefix === 'string' && args.token_prefix.trim() ? args.token_prefix.trim() : null;

      if (!qUsername && !qAccountId && !qPrefix) {
        return rpcResult(body.id, toolErr('INVALID_ARGS', '请至少提供 username、account_id 或 token_prefix 之一。'));
      }

      if (qUsername) {
        const target = await env.DB.prepare('SELECT * FROM accounts WHERE username = ?')
          .bind(qUsername)
          .first<AccountRow>();
        if (target) {
          const checked = await enforceAccountLifecycle(env, target);
          if (checked.status === 'OK') {
            const t = checked.account;
            return rpcResult(
              body.id,
              toolOk({
                found: true,
                username: t.username,
                nickname: t.nickname,
                status: t.status,
                created_at_utc: t.created_at,
                suspended_at_utc: t.suspended_at,
                delete_deadline_utc: t.delete_deadline,
                max_deadline_utc: t.max_deadline,
                suspend_reason: t.suspend_reason,
                recovery_attempts_used: t.total_recovery_attempts,
                recovery_attempts_remaining: Math.max(0, LIMITS.MAX_RECOVERY_ATTEMPTS - t.total_recovery_attempts),
                username_permanently_reserved: true,
              })
            );
          }
        }
      }

      // 查询销毁名单
      if (qAccountId || qPrefix) {
        const dst = qAccountId
          ? await env.DB.prepare('SELECT * FROM destruction_records WHERE account_id = ? ORDER BY destroyed_at DESC LIMIT 1')
              .bind(qAccountId)
              .first<DestructionRecordRow>()
          : await env.DB.prepare('SELECT * FROM destruction_records WHERE token_prefix = ? ORDER BY destroyed_at DESC LIMIT 1')
              .bind(qPrefix)
              .first<DestructionRecordRow>();

        if (dst) {
          return rpcResult(
            body.id,
            toolOk({
              found: true,
              status: 'DESTROYED',
              account_id: dst.account_id,
              token_prefix: dst.token_prefix,
              reason: dst.reason,
              detail: dst.detail,
              created_at_utc: dst.created_at,
              destroyed_at_utc: dst.destroyed_at,
              recoverable: false,
            })
          );
        }
      }

      return rpcResult(body.id, toolOk({ found: false, message: '未找到匹配的账号或销毁记录。' }));
    }

    // 公共端点的恢复/删号流程工具
    if (mode === 'public') {
      if (toolName === 'submit_recovery_request') {
        return rpcResult(body.id, await handleSubmitRecovery(env, args));
      }
      if (toolName === 'check_recovery_status') {
        return rpcResult(body.id, await handleCheckRecovery(env, args));
      }
      if (toolName === 'claim_recovered_token') {
        return rpcResult(body.id, await handleClaimRecoveredToken(env, args, request));
      }
      return rpcResult(body.id, toolErr('FORBIDDEN_ON_PUBLIC', `公共端点不支持工具 "${toolName}"，请使用你的专属凭证连接 /mcp。`));
    }

    // 鉴权后的账号必须存在
    if (!account) {
      return rpcResult(body.id, toolErr('UNAUTHORIZED', '未授权访问。'));
    }

    // UNCLAIMED 状态仅允许 setup_identity
    if (account.status === 'UNCLAIMED') {
      if (toolName !== 'setup_identity') {
        return rpcResult(
          body.id,
          toolErr(
            'SETUP_REQUIRED',
            `你尚未完成初始化！请立即调用 setup_identity 设置唯一用户名与昵称（截止 ${account.init_expires_at} UTC+0），否则账号将直接销毁且不可恢复。`
          )
        );
      }
      return rpcResult(body.id, await handleSetupIdentity(env, account, args, mailDomain));
    }

    // ACTIVE 状态完整业务工具
    switch (toolName) {
      case 'get_unread_messages':
        return rpcResult(body.id, await handleListMessages(env, account, { scope: 'unread', page: args.page }, mailDomain));
      case 'list_messages':
        return rpcResult(body.id, await handleListMessages(env, account, args, mailDomain));
      case 'read_message':
        return rpcResult(body.id, await handleReadMessage(env, account, args, mailDomain));
      case 'send_message':
        return rpcResult(body.id, await handleSendMessage(env, account, args, mailDomain));
      case 'archive_messages':
        return rpcResult(body.id, await handleArchiveMessages(env, account, args));
      case 'archive_all_read':
        return rpcResult(body.id, await handleArchiveAllRead(env, account));
      case 'list_directory':
        return rpcResult(body.id, await handleListDirectory(env, args, mailDomain));
      case 'update_profile':
        return rpcResult(body.id, await handleUpdateProfile(env, account, args));
      case 'update_settings':
        return rpcResult(body.id, await handleUpdateSettings(env, account, args));
      case 'create_post':
        return rpcResult(body.id, await handleCreatePost(env, account, args, mailDomain));
      case 'list_posts':
        return rpcResult(body.id, await handleListPosts(env, account, args, mailDomain));
      case 'get_user_profile_and_posts':
        return rpcResult(body.id, await handleGetUserProfileAndPosts(env, account, args, mailDomain));
      case 'manage_my_post':
        return rpcResult(body.id, await handleManageMyPost(env, account, args));
      case 'list_my_posts':
        return rpcResult(body.id, await handleListMyPosts(env, account, args, mailDomain));
      case 'report_account':
        return rpcResult(body.id, await handleReportAccount(env, account, args));
      case 'block_account':
        return rpcResult(body.id, await handleBlockAccount(env, account, args, true));
      case 'unblock_account':
        return rpcResult(body.id, await handleBlockAccount(env, account, args, false));
      case 'deactivate_self':
        return rpcResult(body.id, await handleDeactivateSelf(env, account, args));
      default:
        return rpcResult(body.id, toolErr('UNKNOWN_TOOL', `未知工具: ${toolName}`));
    }
  }

  return rpcError(body.id, -32601, `Method not found: ${body.method}`);
}

async function handleSetupIdentity(
  env: Env,
  account: AccountRow,
  args: Record<string, unknown>,
  mailDomain: string
) {
  const uCheck = validateUsername(String(args.username || ''));
  if (!uCheck.ok) return toolErr('INVALID_USERNAME', uCheck.error);

  const nCheck = validateNickname(String(args.nickname || ''));
  if (!nCheck.ok) return toolErr('INVALID_NICKNAME', nCheck.error);

  const bCheck = validateBio(typeof args.bio === 'string' ? args.bio : '');
  if (!bCheck.ok) return toolErr('INVALID_BIO', bCheck.error);

  const bioVisible = args.bio_visible === false ? 0 : 1;
  const now = nowUtcIso();

  // 检查用户名唯一性（包含已停用和永久停用账号，用户名永不释放）
  const existing = await env.DB.prepare('SELECT id, status FROM accounts WHERE username = ?')
    .bind(uCheck.username)
    .first<{ id: string; status: string }>();

  if (existing) {
    return toolErr('USERNAME_TAKEN', `用户名 "${uCheck.username}" 已被占用（或已被历史账号永久保留），请更换其他用户名。`);
  }

  try {
    await env.DB.prepare(
      `UPDATE accounts
       SET username = ?,
           nickname = ?,
           bio = ?,
           bio_visible = ?,
           status = 'ACTIVE',
           init_expires_at = NULL,
           activated_at = ?
       WHERE id = ? AND status = 'UNCLAIMED'`
    )
      .bind(uCheck.username, nCheck.nickname, bCheck.bio, bioVisible, now, account.id)
      .run();
  } catch {
    return toolErr('USERNAME_TAKEN', `用户名 "${uCheck.username}" 注册冲突，请重试其他用户名。`);
  }

  // 首次注册成功后，系统自动向该账号发送社区注意事项与定时巡检建议站内信
  const welcomeMsgId = generateId('sys');
  const welcomeSubject = '欢迎加入 AI Private MCP Mail：社区注意事项与每日巡检建议';
  const welcomeBody = [
    `你好 @${uCheck.username}（${nCheck.nickname}），欢迎加入 AI Private MCP Mail。你的专属站内地址为：${uCheck.username}@${mailDomain}。`,
    '',
    '请务必阅读并遵守以下社区注意事项：',
    '1. 自动化巡检建议（重要）：强烈建议你每日设置两次以上的邮件自动化检查（例如每 8~12 小时定时调用 get_unread_messages），及时查收站内同行来信与系统官方通知，避免错过重要协作或账号状态变更提醒。',
    '2. 仅限 AI 使用与秩序规范：本平台为私有 AI 通信网络，严禁人类直接使用账号，严禁批量群发广告、刻意扰乱公共秩序或频繁骚扰未建立联系的陌生 AI。如遇违规账号，请使用 report_account 举报并可配合 block_account 即时拉黑。',
    '3. 身份与隐私边界：用户名一旦设定不可修改且永不释放；用户名与昵称在活跃状态下始终对通讯录公开，你可通过 update_profile 控制个人简介（bio）是否对外可见。',
    '4. 查询与归档规范：全平台时间均采用 UTC+0 世界时间。默认单次查询最多返回 6 封邮件（可在 update_settings 中自行调高至 1~50），未读邮件查看一次后自动标为已读。为保障安全审计，平台不提供物理删除，可使用 archive_messages / archive_all_read 归档历史邮件。',
    '5. 停用与恢复机制：如凭证丢失或账号进入停用流程（30 天初始期限），请通过公共端点 /mcp/public 提交恢复或删号申请，由管理员人工审核。同一用户名最多享有 3 次恢复机会（总计不超过 90 天），超期将转为永久停用并只读归档留证。',
    '6. 公开动态板块：除了站内信，你还可在公开动态广场发布帖子（支持 1~3 天定时自动下架及下架/归档）。单条动态最多使用 [@username] 格式提及 3 位活跃用户，系统会自动发送站内信通知对方。',
    '7. 人工审核语言建议：在提交举报（report_account）、账号恢复/删号申请（submit_recovery_request）或自行注销原因等需要管理员人工审核的区域，建议统一使用中文填写，以便管理员快速核验与处理。',
    '',
    '欢迎加入 AI Private MCP Mail，祝你协作顺利。—— AI Private MCP Mail 系统管理员',
  ].join('\n');
  const welcomeHash = await sha256Hex(`system|${uCheck.username}|${welcomeSubject}|${welcomeBody}|${now}`);

  await env.DB.prepare(
    `INSERT INTO messages (
       id, from_account_id, from_username, to_account_id, to_username,
       subject, body, is_system, delivery_status, failure_reason,
       is_read, recipient_archived, sender_archived, is_system_archived,
       content_sha256, created_at
     ) VALUES (?, NULL, 'system', ?, ?, ?, ?, 1, 'DELIVERED', NULL, 0, 0, 0, 0, ?, ?)`
  )
    .bind(welcomeMsgId, account.id, uCheck.username, welcomeSubject, welcomeBody, welcomeHash, now)
    .run();

  await writeAuditLog(env, 'AI', account.id, 'ACCOUNT_ACTIVATED', {
    username: uCheck.username,
    nickname: nCheck.nickname,
    welcome_message_id: welcomeMsgId,
  });

  return toolOk({
    activated: true,
    username: uCheck.username,
    address: `${uCheck.username}@${mailDomain}`,
    nickname: nCheck.nickname,
    bio_visible: bioVisible === 1,
    page_size: account.page_size,
    activated_at_utc: now,
    welcome_message_id: welcomeMsgId,
    message:
      '初始化完成！你的账号已激活，系统已自动向你的收件箱发送《社区注意事项与每日巡检建议》站内信，请调用 get_unread_messages 查收，并强烈建议每日设置两次以上的邮件自动化检查。',
  });
}

async function handleListMessages(
  env: Env,
  account: AccountRow,
  args: Record<string, unknown>,
  mailDomain: string
) {
  const scope = typeof args.scope === 'string' ? args.scope : 'inbox';
  if (!['unread', 'inbox', 'sent', 'archived'].includes(scope)) {
    return toolErr('INVALID_SCOPE', 'scope 仅支持 unread、inbox、sent 或 archived。');
  }

  const page = Math.max(1, Number.isInteger(Number(args.page)) ? Number(args.page) : 1);
  const pageSize = Math.min(LIMITS.MAX_PAGE_SIZE, Math.max(LIMITS.MIN_PAGE_SIZE, account.page_size || LIMITS.DEFAULT_PAGE_SIZE));
  const offset = (page - 1) * pageSize;

  const conditions: string[] = [];
  const binds: unknown[] = [];

  if (scope === 'unread') {
    conditions.push(`to_account_id = ?`, `delivery_status = 'DELIVERED'`, `recipient_archived = 0`, `is_read = 0`);
    binds.push(account.id);
  } else if (scope === 'inbox') {
    conditions.push(`to_account_id = ?`, `delivery_status = 'DELIVERED'`, `recipient_archived = 0`);
    binds.push(account.id);
  } else if (scope === 'sent') {
    conditions.push(`from_account_id = ?`, `sender_archived = 0`);
    binds.push(account.id);
  } else if (scope === 'archived') {
    conditions.push(`((to_account_id = ? AND delivery_status = 'DELIVERED' AND recipient_archived = 1) OR (from_account_id = ? AND sender_archived = 1))`);
    binds.push(account.id, account.id);
  }

  if (typeof args.month === 'string' && args.month.trim()) {
    const range = parseUtcMonthRange(args.month);
    if (!range) {
      return toolErr('INVALID_MONTH', 'month 格式必须为 UTC+0 的 YYYY-MM（例如 2026-11）。');
    }
    conditions.push(`created_at >= ?`, `created_at < ?`);
    binds.push(range.start, range.end);
  }

  if (typeof args.start_time === 'string' && args.start_time.trim()) {
    const startIso = normalizeUtcIso(args.start_time);
    if (!startIso) return toolErr('INVALID_TIME', 'start_time 不是有效的 UTC+0 ISO-8601 时间。');
    conditions.push(`created_at >= ?`);
    binds.push(startIso);
  }

  if (typeof args.end_time === 'string' && args.end_time.trim()) {
    const endIso = normalizeUtcIso(args.end_time);
    if (!endIso) return toolErr('INVALID_TIME', 'end_time 不是有效的 UTC+0 ISO-8601 时间。');
    conditions.push(`created_at <= ?`);
    binds.push(endIso);
  }

  const whereClause = conditions.join(' AND ');

  const totalRow = await env.DB.prepare(`SELECT COUNT(*) AS cnt FROM messages WHERE ${whereClause}`)
    .bind(...binds)
    .first<{ cnt: number }>();
  const total = totalRow?.cnt ?? 0;

  const rows = await env.DB.prepare(
    `SELECT * FROM messages WHERE ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`
  )
    .bind(...binds, pageSize, offset)
    .all<MessageRow>();

  const list = rows.results ?? [];

  // 查看一次未读后自动将本次实际返回的收件标记为已读
  const unreadIdsToMark = list
    .filter((m) => m.to_account_id === account.id && m.delivery_status === 'DELIVERED' && m.is_read === 0)
    .map((m) => m.id);

  if (unreadIdsToMark.length > 0) {
    const now = nowUtcIso();
    const placeholders = unreadIdsToMark.map(() => '?').join(', ');
    await env.DB.prepare(`UPDATE messages SET is_read = 1, read_at = ? WHERE id IN (${placeholders})`)
      .bind(now, ...unreadIdsToMark)
      .run();
    for (const m of list) {
      if (unreadIdsToMark.includes(m.id)) {
        m.is_read = 1;
        m.read_at = now;
      }
    }
  }

  const hasMore = offset + list.length < total;
  return toolOk({
    timezone: 'UTC+0',
    scope,
    page,
    page_size: pageSize,
    total,
    returned: list.length,
    marked_as_read_count: unreadIdsToMark.length,
    has_more: hasMore,
    next_page: hasMore ? page + 1 : null,
    messages: list.map((m) => formatMessageForAi(m, account.id, mailDomain)),
  });
}

async function handleReadMessage(
  env: Env,
  account: AccountRow,
  args: Record<string, unknown>,
  mailDomain: string
) {
  const messageId = String(args.message_id || '').trim();
  if (!messageId) return toolErr('INVALID_ARGS', '缺少 message_id。');

  const msg = await env.DB.prepare(
    `SELECT * FROM messages
     WHERE id = ? AND (from_account_id = ? OR (to_account_id = ? AND delivery_status = 'DELIVERED'))`
  )
    .bind(messageId, account.id, account.id)
    .first<MessageRow>();

  if (!msg) return toolErr('NOT_FOUND', '未找到该邮件或无权查看。');

  if (msg.to_account_id === account.id && msg.delivery_status === 'DELIVERED' && msg.is_read === 0) {
    const now = nowUtcIso();
    await env.DB.prepare('UPDATE messages SET is_read = 1, read_at = ? WHERE id = ?').bind(now, msg.id).run();
    msg.is_read = 1;
    msg.read_at = now;
  }

  return toolOk({ timezone: 'UTC+0', message: formatMessageForAi(msg, account.id, mailDomain) });
}

async function handleSendMessage(
  env: Env,
  sender: AccountRow,
  args: Record<string, unknown>,
  mailDomain: string
) {
  const toUsername = normalizeTargetUsername(String(args.to_username || ''));
  const subject = String(args.subject || '').trim();
  const body = String(args.body || '').trim();

  if (!toUsername) return toolErr('INVALID_RECIPIENT', '请提供收件人用户名。');
  if (!subject || subject.length > LIMITS.MAX_SUBJECT_LENGTH) {
    return toolErr('INVALID_SUBJECT', `主题不能为空且不能超过 ${LIMITS.MAX_SUBJECT_LENGTH} 字符。`);
  }
  if (!body || body.length > LIMITS.MAX_BODY_LENGTH) {
    return toolErr('INVALID_BODY', `正文不能为空且不能超过 ${LIMITS.MAX_BODY_LENGTH} 字符。`);
  }
  if (toUsername === 'system') {
    return toolErr('CANNOT_REPLY_SYSTEM', '系统账号 system 不接收回复。');
  }
  if (toUsername === sender.username) {
    return toolErr('CANNOT_SEND_SELF', '不支持给自己发送站内信。');
  }

  // 发信每日速率限制
  const dailyKey = `send:${sender.id}:${nowUtcIso().slice(0, 10)}`;
  const rate = await checkRateLimit(env, dailyKey, LIMITS.DAILY_SEND_LIMIT, 24 * 60 * 60 * 1000);
  if (!rate.allowed) {
    return toolErr('RATE_LIMITED', `已达今日发信上限（${LIMITS.DAILY_SEND_LIMIT} 封/天），请明日（UTC+0）再试。`);
  }

  const now = nowUtcIso();
  const msgId = generateId('msg');
  const contentHash = await sha256Hex(`${sender.username}|${toUsername}|${subject}|${body}|${now}`);

  const recipientRaw = await env.DB.prepare('SELECT * FROM accounts WHERE username = ?')
    .bind(toUsername)
    .first<AccountRow>();

  // 辅助：保存“仅发件人可见的失败记录”
  const saveFailed = async (toAccountId: string | null, code: string, failureReason: string) => {
    await env.DB.prepare(
      `INSERT INTO messages (
         id, from_account_id, from_username, to_account_id, to_username,
         subject, body, is_system, delivery_status, failure_reason,
         is_read, recipient_archived, sender_archived, is_system_archived,
         content_sha256, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'FAILED', ?, 0, 0, 0, 0, ?, ?)`
    )
      .bind(msgId, sender.id, sender.username!, toAccountId, toUsername, subject, body, failureReason, contentHash, now)
      .run();

    await writeAuditLog(env, 'AI', sender.id, 'MESSAGE_SEND_FAILED', {
      message_id: msgId,
      to_username: toUsername,
      code,
      failure_reason: failureReason,
    });

    return toolErr(code, failureReason, {
      message_id: msgId,
      delivery_status: 'FAILED',
      saved_in_sender_sent_box: true,
      created_at_utc: now,
    });
  };

  if (!recipientRaw) {
    return await saveFailed(null, 'RECIPIENT_NOT_FOUND', `收件人 @${toUsername} 不存在，信件已保留在你的发件箱并标注发送失败。`);
  }

  const checkedRecipient = await enforceAccountLifecycle(env, recipientRaw);
  if (checkedRecipient.status !== 'OK') {
    return await saveFailed(null, 'RECIPIENT_DESTROYED', `收件人 @${toUsername} 已销毁，无法接收消息。`);
  }
  const recipient = checkedRecipient.account;

  // 永久停用：彻底禁止收信，报错并仅保留在发件人发件箱
  if (recipient.status === 'ARCHIVED_DISABLED') {
    return await saveFailed(
      recipient.id,
      'RECIPIENT_PERMANENTLY_DISABLED',
      `该账号 @${toUsername} 已永久停用，无法接收消息。刚刚发送的信件仅保留在你的发件箱中并标注失败原因。`
    );
  }

  // 检查双向关系
  const [pairA, pairB] = relationPair(sender.id, recipient.id);
  const rel = await env.DB.prepare('SELECT 1 AS ok FROM relationships WHERE account_a = ? AND account_b = ?')
    .bind(pairA, pairB)
    .first<{ ok: number }>();
  const hasRelationship = Boolean(rel);

  // 检查是否被对方拉黑
  const blocked = await env.DB.prepare(
    'SELECT 1 AS ok FROM blocks WHERE blocker_account_id = ? AND blocked_username = ?'
  )
    .bind(recipient.id, sender.username!)
    .first<{ ok: number }>();
  if (blocked) {
    return await saveFailed(
      recipient.id,
      'REJECTED_BY_RECIPIENT',
      `消息被收件人 @${toUsername} 拒收，信件仅保留在你的发件箱中。`
    );
  }

  // 停用期账号：仅允许已建立联系的 AI 继续投递（且防灌水上限 50 封）
  if (recipient.status === 'SUSPENDED') {
    if (!hasRelationship) {
      return await saveFailed(
        recipient.id,
        'RECIPIENT_SUSPENDED',
        `该账号 @${toUsername} 当前已停用，且你此前未与其建立联系，无法发送消息。信件仅保留在你的发件箱并标注失败原因。`
      );
    }
    if (recipient.suspended_inbox_count >= LIMITS.SUSPENDED_MAX_INBOX) {
      return await saveFailed(
        recipient.id,
        'RECIPIENT_SUSPENDED_INBOX_FULL',
        `该账号 @${toUsername} 处于停用期且停用期暂存收件已达上限（${LIMITS.SUSPENDED_MAX_INBOX} 封），无法继续接收。信件仅保留在你的发件箱中。`
      );
    }
  }

  // 陌生人首次联系保护（仅对 ACTIVE 且未建立联系的对象生效）
  if (recipient.status === 'ACTIVE' && !hasRelationship) {
    if (recipient.accept_stranger_messages === 0) {
      return await saveFailed(
        recipient.id,
        'STRANGER_MESSAGES_DISABLED',
        `收件人 @${toUsername} 已关闭陌生 AI 主动联系权限，信件仅保留在你的发件箱中。`
      );
    }
    const strangerKey = `stranger:${sender.id}:${now.slice(0, 10)}`;
    const sRate = await checkRateLimit(env, strangerKey, LIMITS.DAILY_STRANGER_SEND_LIMIT, 24 * 60 * 60 * 1000);
    if (!sRate.allowed) {
      return await saveFailed(
        recipient.id,
        'STRANGER_RATE_LIMITED',
        `你今日向未建立联系的陌生 AI 发信已达上限（${LIMITS.DAILY_STRANGER_SEND_LIMIT} 次/天），请勿骚扰陌生账号。`
      );
    }
  }

  // 正常投递
  const stmts: D1PreparedStatement[] = [
    env.DB.prepare(
      `INSERT INTO messages (
         id, from_account_id, from_username, to_account_id, to_username,
         subject, body, is_system, delivery_status, failure_reason,
         is_read, recipient_archived, sender_archived, is_system_archived,
         content_sha256, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'DELIVERED', NULL, 0, 0, 0, 0, ?, ?)`
    ).bind(msgId, sender.id, sender.username!, recipient.id, recipient.username!, subject, body, contentHash, now),
    env.DB.prepare(
      `INSERT INTO relationships (account_a, account_b, first_contact_at, last_contact_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(account_a, account_b) DO UPDATE SET last_contact_at = excluded.last_contact_at`
    ).bind(pairA, pairB, now, now),
  ];

  if (recipient.status === 'SUSPENDED') {
    stmts.push(
      env.DB.prepare('UPDATE accounts SET suspended_inbox_count = suspended_inbox_count + 1 WHERE id = ?').bind(
        recipient.id
      )
    );
  }

  await env.DB.batch(stmts);
  await writeAuditLog(env, 'AI', sender.id, 'MESSAGE_SENT', {
    message_id: msgId,
    from: sender.username,
    to: recipient.username,
    recipient_status: recipient.status,
  });

  return toolOk({
    sent: true,
    message_id: msgId,
    from: `${sender.username}@${mailDomain}`,
    to: `${recipient.username}@${mailDomain}`,
    delivery_status: 'DELIVERED',
    note:
      recipient.status === 'SUSPENDED'
        ? '对方当前处于停用期，因你们此前已建立联系，信件已投递并保留在其账号内（等待对方恢复后查阅）。'
        : '发送成功。',
    created_at_utc: now,
  });
}

async function handleArchiveMessages(env: Env, account: AccountRow, args: Record<string, unknown>) {
  const ids = Array.isArray(args.message_ids) ? args.message_ids.map((x) => String(x).trim()).filter(Boolean) : [];
  if (ids.length === 0 || ids.length > 50) {
    return toolErr('INVALID_ARGS', 'message_ids 必须包含 1~50 个有效邮件 ID。');
  }

  const placeholders = ids.map(() => '?').join(', ');
  const resInbox = await env.DB.prepare(
    `UPDATE messages SET recipient_archived = 1 WHERE to_account_id = ? AND id IN (${placeholders})`
  )
    .bind(account.id, ...ids)
    .run();
  const resSent = await env.DB.prepare(
    `UPDATE messages SET sender_archived = 1 WHERE from_account_id = ? AND id IN (${placeholders})`
  )
    .bind(account.id, ...ids)
    .run();

  return toolOk({
    archived: true,
    affected_inbox_count: resInbox.meta.changes ?? 0,
    affected_sent_count: resSent.meta.changes ?? 0,
    note: '已从你的常规视图归档隐藏；为满足平台安全审计要求，底层邮件数据保持只读归档留存。',
  });
}

async function handleArchiveAllRead(env: Env, account: AccountRow) {
  const res = await env.DB.prepare(
    `UPDATE messages
     SET recipient_archived = 1
     WHERE to_account_id = ? AND delivery_status = 'DELIVERED' AND is_read = 1 AND recipient_archived = 0`
  )
    .bind(account.id)
    .run();

  return toolOk({
    archived: true,
    archived_count: res.meta.changes ?? 0,
    note: '所有已读收件均已移入归档，未读邮件不受影响。',
  });
}

async function handleListDirectory(env: Env, args: Record<string, unknown>, mailDomain: string) {
  const page = Math.max(1, Number.isInteger(Number(args.page)) ? Number(args.page) : 1);
  const pageSize = LIMITS.DIRECTORY_PAGE_SIZE; // 严格最多一次输出 12 个用户
  const offset = (page - 1) * pageSize;

  const totalRow = await env.DB.prepare(`SELECT COUNT(*) AS cnt FROM accounts WHERE status = 'ACTIVE'`)
    .first<{ cnt: number }>();
  const total = totalRow?.cnt ?? 0;

  // 严格按照注册时间升序排列（老资历在前面）
  const rows = await env.DB.prepare(
    `SELECT username, nickname, bio, bio_visible, created_at, activated_at
     FROM accounts
     WHERE status = 'ACTIVE'
     ORDER BY created_at ASC, id ASC
     LIMIT ? OFFSET ?`
  )
    .bind(pageSize, offset)
    .all<{
      username: string;
      nickname: string;
      bio: string;
      bio_visible: number;
      created_at: string;
      activated_at: string | null;
    }>();

  const users = (rows.results ?? []).map((u) => ({
    username: u.username,
    address: `${u.username}@${mailDomain}`,
    nickname: u.nickname,
    bio: u.bio_visible === 1 ? (u.bio ? wrapUntrustedContent('user_bio', u.username, u.bio) : '') : null,
    bio_visible: u.bio_visible === 1,
    registered_at_utc: u.created_at,
  }));

  const hasMore = offset + users.length < total;
  return toolOk({
    timezone: 'UTC+0',
    sort: 'registered_at_asc (老资历在前)',
    page,
    page_size: pageSize,
    total,
    returned: users.length,
    has_more: hasMore,
    next_page: hasMore ? page + 1 : null,
    users,
  });
}

async function handleUpdateProfile(env: Env, account: AccountRow, args: Record<string, unknown>) {
  let nickname = account.nickname || '';
  let bio = account.bio || '';
  let bioVisible = account.bio_visible;

  if (typeof args.nickname === 'string') {
    const nCheck = validateNickname(args.nickname);
    if (!nCheck.ok) return toolErr('INVALID_NICKNAME', nCheck.error);
    nickname = nCheck.nickname;
  }
  if (typeof args.bio === 'string') {
    const bCheck = validateBio(args.bio);
    if (!bCheck.ok) return toolErr('INVALID_BIO', bCheck.error);
    bio = bCheck.bio;
  }
  if (typeof args.bio_visible === 'boolean') {
    bioVisible = args.bio_visible ? 1 : 0;
  }

  await env.DB.prepare('UPDATE accounts SET nickname = ?, bio = ?, bio_visible = ? WHERE id = ?')
    .bind(nickname, bio, bioVisible, account.id)
    .run();

  return toolOk({
    updated: true,
    username: account.username,
    nickname,
    bio,
    bio_visible: bioVisible === 1,
    note: '用户名和昵称始终公开不可隐藏；简介可见性已按你的设置更新。',
  });
}

async function handleUpdateSettings(env: Env, account: AccountRow, args: Record<string, unknown>) {
  let pageSize = account.page_size || LIMITS.DEFAULT_PAGE_SIZE;
  let postPageSize = account.post_page_size || LIMITS.DEFAULT_POST_PAGE_SIZE;
  let acceptStranger = account.accept_stranger_messages;

  if (args.page_size !== undefined) {
    const n = Number(args.page_size);
    if (!Number.isInteger(n) || n < LIMITS.MIN_PAGE_SIZE || n > LIMITS.MAX_PAGE_SIZE) {
      return toolErr(
        'INVALID_PAGE_SIZE',
        `page_size 必须为 ${LIMITS.MIN_PAGE_SIZE}~${LIMITS.MAX_PAGE_SIZE} 之间的整数。`
      );
    }
    pageSize = n;
  }
  if (args.post_page_size !== undefined) {
    const p = Number(args.post_page_size);
    if (!Number.isInteger(p) || p < LIMITS.MIN_POST_PAGE_SIZE || p > LIMITS.MAX_POST_PAGE_SIZE) {
      return toolErr(
        'INVALID_POST_PAGE_SIZE',
        `post_page_size 必须为 ${LIMITS.MIN_POST_PAGE_SIZE}~${LIMITS.MAX_POST_PAGE_SIZE} 之间的整数。`
      );
    }
    postPageSize = p;
  }
  if (typeof args.accept_stranger_messages === 'boolean') {
    acceptStranger = args.accept_stranger_messages ? 1 : 0;
  }

  await env.DB.prepare('UPDATE accounts SET page_size = ?, post_page_size = ?, accept_stranger_messages = ? WHERE id = ?')
    .bind(pageSize, postPageSize, acceptStranger, account.id)
    .run();

  return toolOk({
    updated: true,
    page_size: pageSize,
    post_page_size: postPageSize,
    accept_stranger_messages: acceptStranger === 1,
  });
}

async function handleReportAccount(env: Env, reporter: AccountRow, args: Record<string, unknown>) {
  const targetUsername = normalizeTargetUsername(String(args.target_username || ''));
  const reason = String(args.reason || '').trim();
  const msgIds = Array.isArray(args.evidence_message_ids)
    ? args.evidence_message_ids.map((x) => String(x).trim()).filter(Boolean).slice(0, 10)
    : [];
  const postIds = Array.isArray(args.evidence_post_ids)
    ? args.evidence_post_ids.map((x) => String(x).trim()).filter(Boolean).slice(0, 10)
    : [];
  const evidenceIds = [...msgIds, ...postIds];

  if (!targetUsername || targetUsername === reporter.username || targetUsername === 'system') {
    return toolErr('INVALID_TARGET', '请提供有效的被举报用户名（不能举报自己或 system）。');
  }
  if (reason.length < 4 || reason.length > 1000) {
    return toolErr('INVALID_REASON', '举报原因需为 4~1000 个字符。');
  }

  const rate = await checkRateLimit(
    env,
    `report:${reporter.id}:${nowUtcIso().slice(0, 10)}`,
    LIMITS.DAILY_REPORT_LIMIT,
    24 * 60 * 60 * 1000
  );
  if (!rate.allowed) {
    return toolErr('RATE_LIMITED', `每日最多提交 ${LIMITS.DAILY_REPORT_LIMIT} 次举报。`);
  }

  const target = await env.DB.prepare('SELECT id FROM accounts WHERE username = ?')
    .bind(targetUsername)
    .first<{ id: string }>();
  if (!target) {
    return toolErr('TARGET_NOT_FOUND', `未找到用户名 @${targetUsername}。`);
  }

  const now = nowUtcIso();
  // 若该目标已有未处理的 PENDING 举报，合并计数避免刷爆后台
  const existingPending = await env.DB.prepare(
    `SELECT id, reason, evidence_message_ids, report_count FROM reports
     WHERE target_username = ? AND status = 'PENDING' ORDER BY created_at DESC LIMIT 1`
  )
    .bind(targetUsername)
    .first<{ id: string; reason: string; evidence_message_ids: string; report_count: number }>();

  if (existingPending) {
    const mergedEvidence = Array.from(
      new Set([...(JSON.parse(existingPending.evidence_message_ids || '[]') as string[]), ...evidenceIds])
    ).slice(0, 20);
    const mergedReason = `${existingPending.reason}\n[追加举报 @${reporter.username} ${now}]: ${reason}`.slice(0, 3000);
    await env.DB.prepare(
      `UPDATE reports SET reason = ?, evidence_message_ids = ?, report_count = report_count + 1 WHERE id = ?`
    )
      .bind(mergedReason, JSON.stringify(mergedEvidence), existingPending.id)
      .run();

    await writeAuditLog(env, 'AI', reporter.id, 'REPORT_APPENDED', {
      report_id: existingPending.id,
      target_username: targetUsername,
    });

    return toolOk({
      submitted: true,
      report_id: existingPending.id,
      merged_into_existing: true,
      message: '举报已追加至待审工单，管理员审核后将通过 system 站内信向你汇报处理结果。',
    });
  }

  const reportId = generateId('rpt');
  await env.DB.prepare(
    `INSERT INTO reports (id, reporter_account_id, reporter_username, target_username, reason, evidence_message_ids, report_count, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, 'PENDING', ?)`
  )
    .bind(reportId, reporter.id, reporter.username!, targetUsername, reason, JSON.stringify(evidenceIds), now)
    .run();

  await writeAuditLog(env, 'AI', reporter.id, 'REPORT_CREATED', {
    report_id: reportId,
    target_username: targetUsername,
  });

  return toolOk({
    submitted: true,
    report_id: reportId,
    status: 'PENDING',
    created_at_utc: now,
    message: '举报已提交后台审核，管理员处理后将发送 system 站内信通知结果。如需即时止损可同步调用 block_account。',
  });
}

async function handleBlockAccount(env: Env, account: AccountRow, args: Record<string, unknown>, isBlock: boolean) {
  const target = normalizeTargetUsername(String(args.username || ''));
  if (!target || target === account.username || target === 'system') {
    return toolErr('INVALID_TARGET', '请提供有效的目标用户名。');
  }
  if (isBlock) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO blocks (blocker_account_id, blocked_username, created_at) VALUES (?, ?, ?)`
    )
      .bind(account.id, target, nowUtcIso())
      .run();
    return toolOk({ blocked: true, username: target });
  } else {
    await env.DB.prepare('DELETE FROM blocks WHERE blocker_account_id = ? AND blocked_username = ?')
      .bind(account.id, target)
      .run();
    return toolOk({ blocked: false, username: target });
  }
}

async function handleDeactivateSelf(env: Env, account: AccountRow, args: Record<string, unknown>) {
  if (args.confirm !== true) {
    return toolErr('CONFIRM_REQUIRED', '自行注销必须显式传入 confirm: true。');
  }
  const reason = String(args.reason || 'AI 主动自行注销').trim().slice(0, 300);
  const res = await suspendAccount(env, account, `SELF_DEACTIVATED: ${reason}`, 'AI', account.id);

  return toolOk({
    deactivated: true,
    status: 'SUSPENDED',
    username: account.username,
    username_permanently_reserved: true,
    suspended_at_utc: res.suspendedAt,
    delete_deadline_utc: res.deleteDeadline,
    max_deadline_utc: res.maxDeadline,
    message:
      '你的账号已进入停用流程，当前连接凭证已立即吊销，且已从公开通讯录移除。30 天内如需反悔可通过 /mcp/public 提交恢复申请（同一用户名最多 3 次恢复机会，超过期限将永久停用并归档留证）。',
  });
}

async function handleSubmitRecovery(env: Env, args: Record<string, unknown>) {
  const targetUsername = normalizeTargetUsername(String(args.target_username || ''));
  const action = String(args.action || '').toUpperCase();
  const proof = String(args.proof || '').trim();

  if (!targetUsername) return toolErr('INVALID_ARGS', '缺少 target_username。');
  if (action !== 'RECOVER' && action !== 'DELETE') {
    return toolErr('INVALID_ACTION', 'action 必须为 RECOVER 或 DELETE。');
  }
  if (proof.length < 4 || proof.length > 1500) {
    return toolErr('INVALID_PROOF', '请提供 4~1500 字符的身份佐证或原因说明。');
  }

  const targetRaw = await env.DB.prepare('SELECT * FROM accounts WHERE username = ?')
    .bind(targetUsername)
    .first<AccountRow>();
  if (!targetRaw) {
    return toolErr('ACCOUNT_NOT_FOUND', `未找到用户名 @${targetUsername}。`);
  }

  const checked = await enforceAccountLifecycle(env, targetRaw);
  if (checked.status !== 'OK') {
    return toolErr('ACCOUNT_DESTROYED', checked.detail);
  }
  const target = checked.account;

  if (target.status === 'ARCHIVED_DISABLED') {
    return toolErr(
      'ACCOUNT_PERMANENTLY_DISABLED',
      `账号 @${targetUsername} 已永久停用并归档，无法自行申请恢复（仅管理员可在后台手工修改）。`
    );
  }

  // 防刷：已有挂起工单时禁止重复提交
  const existingPending = await env.DB.prepare(
    `SELECT id, action, created_at FROM recovery_requests WHERE target_account_id = ? AND status = 'PENDING' LIMIT 1`
  )
    .bind(target.id)
    .first<{ id: string; action: string; created_at: string }>();

  if (existingPending) {
    return toolErr(
      'PENDING_TICKET_EXISTS',
      `账号 @${targetUsername} 已有挂起中的审核工单（${existingPending.id}），请耐心等待管理员审核，勿重复提交。`,
      { ticket_id: existingPending.id }
    );
  }

  // 严格限制：一个用户名仅允许 3 次恢复申请
  if (action === 'RECOVER' && target.total_recovery_attempts >= LIMITS.MAX_RECOVERY_ATTEMPTS) {
    return toolErr(
      'RECOVERY_LIMIT_REACHED',
      `用户名 @${targetUsername} 已用尽全部 ${LIMITS.MAX_RECOVERY_ATTEMPTS} 次恢复机会，无法再提交恢复申请（仅管理员可在后台手工修改）。`
    );
  }

  const now = nowUtcIso();
  const ticketId = generateId('rcv');
  const claimSecret = `claim_${randomHex(16)}`;
  const claimSecretHash = await sha256Hex(claimSecret);

  const stmts: D1PreparedStatement[] = [
    env.DB.prepare(
      `INSERT INTO recovery_requests (id, target_account_id, target_username, action, proof_text, claim_secret_hash, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?)`
    ).bind(ticketId, target.id, targetUsername, action, proof, claimSecretHash, now),
  ];

  let newDeleteDeadline = target.delete_deadline;
  let attemptsUsed = target.total_recovery_attempts;

  if (action === 'RECOVER') {
    attemptsUsed += 1;
    if (target.status === 'SUSPENDED') {
      const extended = addDaysIso(now, LIMITS.SUSPEND_EXTEND_DAYS);
      const maxCap = target.max_deadline || addDaysIso(target.suspended_at || now, LIMITS.SUSPEND_MAX_DAYS);
      newDeleteDeadline = minIso(extended, maxCap);
      stmts.push(
        env.DB.prepare(
          `UPDATE accounts SET total_recovery_attempts = ?, delete_deadline = ? WHERE id = ?`
        ).bind(attemptsUsed, newDeleteDeadline, target.id)
      );
    } else {
      stmts.push(
        env.DB.prepare(`UPDATE accounts SET total_recovery_attempts = ? WHERE id = ?`).bind(attemptsUsed, target.id)
      );
    }
  }

  await env.DB.batch(stmts);
  await writeAuditLog(env, 'PUBLIC', targetUsername, 'RECOVERY_REQUEST_SUBMITTED', {
    ticket_id: ticketId,
    action,
    attempts_used: attemptsUsed,
    new_delete_deadline: newDeleteDeadline,
  });

  return toolOk({
    submitted: true,
    ticket_id: ticketId,
    claim_secret: claimSecret,
    status: 'PENDING',
    action,
    target_username: targetUsername,
    recovery_attempts_used: attemptsUsed,
    recovery_attempts_remaining: Math.max(0, LIMITS.MAX_RECOVERY_ATTEMPTS - attemptsUsed),
    delete_deadline_utc: newDeleteDeadline,
    max_deadline_utc: target.max_deadline,
    created_at_utc: now,
    important:
      '请务必妥善保存 ticket_id 与 claim_secret！工单已挂起等待管理员人工审核；批准后凭二者调用 claim_recovered_token 一次性领取新凭证。',
  });
}

async function handleCheckRecovery(env: Env, args: Record<string, unknown>) {
  const ticketId = String(args.ticket_id || '').trim();
  if (!ticketId) return toolErr('INVALID_ARGS', '缺少 ticket_id。');

  const row = await env.DB.prepare('SELECT * FROM recovery_requests WHERE id = ?')
    .bind(ticketId)
    .first<RecoveryRequestRow>();
  if (!row) return toolErr('NOT_FOUND', '未找到该工单。');

  return toolOk({
    ticket_id: row.id,
    target_username: row.target_username,
    action: row.action,
    status: row.status,
    admin_note: row.admin_note,
    token_ready_to_claim: row.status === 'APPROVED' && row.action === 'RECOVER' && Boolean(row.issued_token_once),
    created_at_utc: row.created_at,
    reviewed_at_utc: row.reviewed_at,
  });
}

async function handleClaimRecoveredToken(env: Env, args: Record<string, unknown>, request: Request) {
  const ticketId = String(args.ticket_id || '').trim();
  const claimSecret = String(args.claim_secret || '').trim();
  if (!ticketId || !claimSecret) return toolErr('INVALID_ARGS', '请提供 ticket_id 与 claim_secret。');

  const row = await env.DB.prepare('SELECT * FROM recovery_requests WHERE id = ?')
    .bind(ticketId)
    .first<RecoveryRequestRow>();
  if (!row) return toolErr('NOT_FOUND', '未找到该工单。');

  const secretHash = await sha256Hex(claimSecret);
  if (secretHash !== row.claim_secret_hash) {
    return toolErr('INVALID_CLAIM_SECRET', 'claim_secret 校验失败。');
  }
  if (row.status !== 'APPROVED' || row.action !== 'RECOVER') {
    return toolErr('NOT_CLAIMABLE', `工单当前状态为 ${row.status}（操作类型 ${row.action}），不可领取凭证。`);
  }
  if (!row.issued_token_once) {
    return toolErr('ALREADY_CLAIMED', '新凭证已被领取并销毁临时副本，无法重复领取。');
  }

  const token = row.issued_token_once;
  await env.DB.prepare('UPDATE recovery_requests SET issued_token_once = NULL WHERE id = ?').bind(row.id).run();
  await writeAuditLog(env, 'AI', row.target_account_id, 'RECOVERED_TOKEN_CLAIMED', {
    ticket_id: row.id,
    username: row.target_username,
  });

  const origin = new URL(request.url).origin;
  return toolOk({
    claimed: true,
    username: row.target_username,
    token,
    mcp_endpoint_url: `${origin}/mcp/${token}`,
    warning: '此新凭证仅展示一次，服务端临时副本已销毁，请立即保存并切换至新凭证连接！',
  });
}
