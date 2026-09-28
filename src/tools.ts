// Your tools go here. Four are included so the first connection has something
// to call — and so the identity is seen doing real work. Replace them.
//
// `authInfo.extra.identity` is the verified Identity from auth.ts — the same
// person on every call, checked on every request. Use `sub` as the stable key
// for anything you store; `email` is verified by ZapQR when `emailVerified`.
//
//   whoami     the identity behind this connection
//   echo       round-trip smoke test
//   remember   save a note — stored under THIS person's sub in KV
//   recall     list this person's notes, and nobody else's
//
// `remember`/`recall` are the point: two people connecting the same server
// each see only their own notes, and neither one ever typed a password or
// pasted an API key. The isolation is one line — the KV key starts with sub.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Identity } from './auth.ts';

export interface ToolEnv {
  NOTES?: KVNamespace;
}

const MAX_NOTES = 50;
const id = (extra: { authInfo?: { extra?: Record<string, unknown> } }) => extra.authInfo?.extra?.identity as Identity | undefined;
const text = (t: string, isError = false) => ({ content: [{ type: 'text' as const, text: t }], ...(isError ? { isError: true } : {}) });

export function buildServer(env: ToolEnv): McpServer {
  const server = new McpServer(
    { name: 'zapqr-mcp-starter', version: '1.1.0' },
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
      const me = id(extra);
      if (!me) return text('No identity on this connection.', true);
      return text([
        `sub: ${me.sub}`,
        `email: ${me.email ?? '(not shared)'}${me.email && me.emailVerified ? ' (verified by ZapQR)' : ''}`,
        `scopes: ${me.scopes.join(' ')}`,
        me.clientId ? `client: ${me.clientId}` : null,
        me.expiresAt ? `token expires: ${new Date(me.expiresAt * 1000).toISOString()}` : null,
      ].filter(Boolean).join('\n'));
    },
  );

  server.registerTool(
    'echo',
    {
      title: 'Echo',
      description: 'Returns what you send, signed with who sent it. A smoke test for the tool round trip.',
      inputSchema: { text: z.string().max(2000).describe('Anything') },
    },
    async ({ text: t }, extra) => {
      const me = id(extra);
      return text(`${t}\n— ${me?.email ?? me?.sub ?? 'anonymous'}`);
    },
  );

  server.registerTool(
    'remember',
    {
      title: 'Remember',
      description: 'Save a short note for the signed-in person. Only they can recall it — notes are stored under their ZapQR account id, never shared.',
      inputSchema: { note: z.string().min(1).max(1000).describe('What to remember') },
    },
    async ({ note }, extra) => {
      const me = id(extra);
      if (!me) return text('No identity on this connection.', true);
      if (!env.NOTES) return text('NOTES KV binding is not configured — see wrangler.toml.', true);
      const key = `${me.sub}:${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`;
      const existing = await env.NOTES.list({ prefix: `${me.sub}:`, limit: MAX_NOTES + 1 });
      if (existing.keys.length >= MAX_NOTES) return text(`You already have ${MAX_NOTES} notes — forget some first.`, true);
      await env.NOTES.put(key, JSON.stringify({ note, at: new Date().toISOString(), by: me.clientId ?? null }));
      return text(`Remembered for ${me.email ?? me.sub}: "${note}"`);
    },
  );

  server.registerTool(
    'recall',
    {
      title: 'Recall',
      description: "List the signed-in person's notes, newest first. Returns nothing that belongs to anyone else.",
      inputSchema: { limit: z.number().int().min(1).max(MAX_NOTES).optional().describe('How many, default 20') },
    },
    async ({ limit }, extra) => {
      const me = id(extra);
      if (!me) return text('No identity on this connection.', true);
      if (!env.NOTES) return text('NOTES KV binding is not configured — see wrangler.toml.', true);
      const { keys } = await env.NOTES.list({ prefix: `${me.sub}:`, limit: MAX_NOTES });
      const rows = await Promise.all(keys.map(async (k) => {
        const v = await env.NOTES!.get(k.name, 'json') as { note: string; at: string } | null;
        return v ? { ...v, key: k.name } : null;
      }));
      const notes = rows.filter((r): r is { note: string; at: string; key: string } => Boolean(r))
        .sort((a, b) => b.at.localeCompare(a.at))
        .slice(0, limit ?? 20);
      if (!notes.length) return text(`No notes yet for ${me.email ?? me.sub}. Use "remember" to add one.`);
      return text(notes.map((n) => `• ${n.note}  (${n.at.slice(0, 16).replace('T', ' ')} UTC)`).join('\n'));
    },
  );

  server.registerTool(
    'forget',
    {
      title: 'Forget',
      description: "Delete all of the signed-in person's notes. Theirs only.",
      inputSchema: {},
    },
    async (_args, extra) => {
      const me = id(extra);
      if (!me) return text('No identity on this connection.', true);
      if (!env.NOTES) return text('NOTES KV binding is not configured — see wrangler.toml.', true);
      const { keys } = await env.NOTES.list({ prefix: `${me.sub}:`, limit: MAX_NOTES });
      await Promise.all(keys.map((k) => env.NOTES!.delete(k.name)));
      return text(`Forgot ${keys.length} note${keys.length === 1 ? '' : 's'} for ${me.email ?? me.sub}.`);
    },
  );

  return server;
}
