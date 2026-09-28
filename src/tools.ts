// Your tools go here. Two are included so the first connection has something
// to call: `whoami` proves the identity made it through, `echo` proves the
// round trip. Replace them.
//
// `authInfo.extra.identity` is the verified Identity from auth.ts — the same
// person on every call, checked on every request. Use `sub` as the stable key
// for anything you store; `email` is verified by ZapQR when `emailVerified`.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Identity } from './auth.ts';

export function buildServer(): McpServer {
  const server = new McpServer(
    { name: 'zapqr-mcp-starter', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  server.registerTool(
    'whoami',
    {
      title: 'Who am I',
      description: 'The ZapQR identity behind this connection: stable account id, verified email, and the scopes granted.',
      inputSchema: {},
    },
    async (_args, extra) => {
      const id = extra.authInfo?.extra?.identity as Identity | undefined;
      if (!id) return { content: [{ type: 'text', text: 'No identity on this connection.' }], isError: true };
      const lines = [
        `sub: ${id.sub}`,
        `email: ${id.email ?? '(not shared)'}${id.email && id.emailVerified ? ' (verified by ZapQR)' : ''}`,
        `scopes: ${id.scopes.join(' ')}`,
        id.clientId ? `client: ${id.clientId}` : null,
        id.expiresAt ? `token expires: ${new Date(id.expiresAt * 1000).toISOString()}` : null,
      ].filter(Boolean);
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );

  server.registerTool(
    'echo',
    {
      title: 'Echo',
      description: 'Returns what you send, signed with who sent it. A smoke test for the tool round trip.',
      inputSchema: { text: z.string().max(2000).describe('Anything') },
    },
    async ({ text }, extra) => {
      const id = extra.authInfo?.extra?.identity as Identity | undefined;
      return { content: [{ type: 'text', text: `${text}\n— ${id?.email ?? id?.sub ?? 'anonymous'}` }] };
    },
  );

  return server;
}
