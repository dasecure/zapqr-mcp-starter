// zapqr-mcp-starter — an MCP server on Cloudflare Workers whose authorization
// server is Sign in with ZapQR (auth.zapqr.ai).
//
//   GET  /.well-known/oauth-protected-resource[/mcp]   RFC 9728 metadata
//   POST /mcp                                            the MCP endpoint (Streamable HTTP)
//   GET  /                                               a page that says what this is
//
// Every request to /mcp needs a bearer token minted by ZapQR for THIS server.
// No token → 401 with WWW-Authenticate pointing at the metadata; the MCP
// client takes it from there (discovers auth.zapqr.ai, registers itself, runs
// the sign-in, comes back with a token). See src/auth.ts.

import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { bearerToken, challenge, protectedResourceMetadata, verifyBearer, DEFAULT_ISSUER, SCOPE } from './auth.ts';
import { buildServer, type ToolEnv } from './tools.ts';

export interface Env extends ToolEnv {
  /** Optional. The authorization server; defaults to https://auth.zapqr.ai. */
  ZAPQR_ISSUER?: string;
  /** Optional. This server's registered identifier. Defaults to <origin>/mcp of the incoming request. */
  RESOURCE?: string;
}

const MCP_PATH = '/mcp';

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, mcp-session-id, mcp-protocol-version, last-event-id',
  'access-control-expose-headers': 'mcp-session-id, www-authenticate',
  'access-control-max-age': '86400',
};

function withCors(res: Response): Response {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(CORS)) out.headers.set(k, v);
  return out;
}

function config(request: Request, env: Env) {
  const url = new URL(request.url);
  return {
    issuer: (env.ZAPQR_ISSUER || DEFAULT_ISSUER).replace(/\/+$/, ''),
    resource: (env.RESOURCE || `${url.origin}${MCP_PATH}`).replace(/\/+$/, ''),
  };
}

function homePage(cfg: { issuer: string; resource: string }): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP server · secured by ZapQR</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 20px;color:#191D28;background:#F4F4EF}
code{font:13px ui-monospace,monospace;background:#fff;border:1px solid #E5E4DC;border-radius:6px;padding:2px 6px}
h1{font-size:22px}a{color:#3B4BDB}dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px}dt{color:#6E7482}</style></head>
<body><h1>This is an MCP server</h1>
<p>Add it to Claude, Cursor or VS Code as a remote MCP server at <code>${cfg.resource}</code>. You'll be asked to sign in with ZapQR — a passkey or a scan from your phone — and to connect the agent to this server. No passwords, no API keys.</p>
<dl><dt>MCP endpoint</dt><dd><code>${cfg.resource}</code></dd>
<dt>Authorization server</dt><dd><code>${cfg.issuer}</code></dd>
<dt>Metadata</dt><dd><a href="/.well-known/oauth-protected-resource">/.well-known/oauth-protected-resource</a></dd>
<dt>Scope</dt><dd><code>${SCOPE}</code></dd></dl>
<p>Built from <a href="https://github.com/dasecure/zapqr-mcp-starter">zapqr-mcp-starter</a>. Guide: <a href="https://zapqr.ai/mcp">zapqr.ai/mcp</a>.</p></body></html>`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=300' } });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cfg = config(request, env);

    if (request.method === 'OPTIONS') return withCors(new Response(null, { status: 204 }));

    // RFC 9728. Both the path-inserted form the spec prefers and the root
    // form older clients try.
    if (url.pathname === '/.well-known/oauth-protected-resource' || url.pathname === `/.well-known/oauth-protected-resource${MCP_PATH}`) {
      return withCors(new Response(JSON.stringify(protectedResourceMetadata(cfg), null, 2), {
        headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600' },
      }));
    }

    if (url.pathname === '/' && request.method === 'GET') return homePage(cfg);

    if (url.pathname !== MCP_PATH) return new Response('Not found', { status: 404 });

    // The gate. Everything past this line has a verified person behind it.
    const verdict = await verifyBearer(bearerToken(request), cfg);
    if (!verdict.ok) return withCors(challenge(cfg, verdict));
    const { identity } = verdict;

    // Stateless: one transport + server per request, no session id, so any
    // Worker isolate can answer any request (2026-07-28 "stateless transport").
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    const server = buildServer(env);
    await server.connect(transport);
    const res = await transport.handleRequest(request, {
      authInfo: {
        token: identity.token,
        clientId: identity.clientId ?? 'unknown',
        scopes: identity.scopes,
        expiresAt: identity.expiresAt,
        resource: new URL(cfg.resource),
        extra: { identity },
      },
    });
    return withCors(res);
  },
} satisfies ExportedHandler<Env>;
