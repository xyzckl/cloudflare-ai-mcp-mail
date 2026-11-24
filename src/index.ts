import { Env } from './types';
import { handleMcpRequest } from './mcp';
import { handleRegisterApi, renderRegisterPage } from './register-page';
import { handleAdminApi, renderAdminPage } from './admin';
import { runScheduledCleanup } from './lifecycle';
import {
  handleAuthorizationServerMetadata,
  handleOAuthAuthorize,
  handleOAuthDynamicRegister,
  handleOAuthToken,
  handleProtectedResourceMetadata,
  MCP_CORS_HEADERS,
} from './oauth';
import { jsonResponse } from './utils';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/favicon.ico') {
      // 默认内置一个中性信封图标；部署者可自行替换为自己的 logo 链接
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#2563eb"/><path d="M12 20h40v24H12z" fill="none" stroke="#fff" stroke-width="4"/><path d="M12 22l20 14 20-14" fill="none" stroke="#fff" stroke-width="4"/></svg>`;
      return new Response(svg, {
        headers: { 'content-type': 'image/svg+xml', 'cache-control': 'public, max-age=86400' },
      });
    }

    // 0. MCP OAuth 2.1 标准发现与授权路由（让客户端连接 /mcp 时自动跳转注册/授权）
    if (
      path === '/.well-known/oauth-protected-resource' ||
      path === '/.well-known/oauth-protected-resource/mcp'
    ) {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: MCP_CORS_HEADERS });
      return handleProtectedResourceMetadata(request);
    }

    if (
      path === '/.well-known/oauth-authorization-server' ||
      path === '/.well-known/openid-configuration'
    ) {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: MCP_CORS_HEADERS });
      return handleAuthorizationServerMetadata(request);
    }

    if (path === '/oauth/register') {
      return handleOAuthDynamicRegister(request, env);
    }
    if (path === '/oauth/authorize') {
      return handleOAuthAuthorize(request, env);
    }
    if (path === '/oauth/token') {
      return handleOAuthToken(request, env);
    }

    // 1. 人类手动注册页面（用于不支持 OAuth 的客户端手动复制凭证）
    if (path === '/' || path === '/register') {
      return renderRegisterPage(env);
    }

    if (path === '/api/register') {
      return handleRegisterApi(request, env);
    }

    // 2. 禁止人类通过网页查询帮助或账号状态
    if (path === '/help' || path === '/status') {
      return jsonResponse(
        {
          error: 'AI_MCP_ONLY',
          message: '账号状态与帮助文档仅限通过 MCP 协议（/mcp 或 /mcp/public）查询，不提供网页查询页面。',
        },
        403
      );
    }

    // 3. 公共 MCP 引导端点（帮助、查状态、提交恢复/删号、查进度、领取新凭证）
    if (path === '/mcp/public') {
      return handleMcpRequest(request, env, 'public');
    }

    // 4. 标准 OAuth / Bearer MCP 端点（无凭证时返回 401 + WWW-Authenticate 自动触发 OAuth 注册）
    if (path === '/mcp') {
      return handleMcpRequest(request, env, 'auth');
    }

    // 5. 路径携带凭证的 MCP 端点（兼容仅支持单 URL 的客户端）
    if (path.startsWith('/mcp/')) {
      const token = decodeURIComponent(path.slice('/mcp/'.length)).trim();
      if (!token || token.includes('/')) {
        return jsonResponse({ error: 'INVALID_MCP_PATH' }, 400);
      }
      return handleMcpRequest(request, env, 'auth', token);
    }

    // 6. 管理员后台与 API
    if (path === '/admin') {
      return renderAdminPage(env);
    }

    if (path.startsWith('/api/admin/')) {
      const subPath = path.slice('/api/admin'.length);
      return handleAdminApi(request, env, subPath);
    }

    return jsonResponse({ error: 'NOT_FOUND' }, 404);
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runScheduledCleanup(env));
  },
};
