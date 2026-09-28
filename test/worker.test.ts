// End to end, without a network: a token minted the way auth.zapqr.ai mints it
// (RS256, typ at+jwt, aud = this server), the Worker's fetch handler called
// directly, and the MCP protocol driven through it.
//
//   npm test        (node --test test/ — type-stripped, no build step)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, exportJWK, generateKeyPair, createLocalJWKSet } from 'jose';
import { verifyBearer, challenge, protectedResourceMetadata, metadataUrl, bearerToken, useKeys, SCOPE } from '../src/auth.ts';
import worker from '../src/index.ts';

const ISSUER = 'https://auth.example.test';
const RESOURCE = 'https://mcp.example.test/mcp';

const { publicKey, privateKey } = await generateKeyPair('RS256');
const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
const keys = createLocalJWKSet({ keys: [jwk] });

async function mint(overrides: Record<string, unknown> = {}, { typ = 'at+jwt', aud = RESOURCE, iss = ISSUER } = {}) {
  return new SignJWT({ scope: `openid ${SCOPE}`, email: 'owner@example.test', email_verified: true, client_id: 'zq_agent', ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ })
    .setIssuer(iss).setAudience(aud).setSubject('u-123').setIssuedAt().setExpirationTime('1h')
    .sign(privateKey);
}

// The Worker reads keys from the issuer's /jwks; point it at the local set.
const cfg = { issuer: ISSUER, resource: RESOURCE, keys };

test('metadata is what RFC 9728 asks for, at the path-inserted URL', () => {
  const doc = protectedResourceMetadata(cfg);
  assert.equal(doc.resource, RESOURCE);
  assert.deepEqual(doc.authorization_servers, [ISSUER]);
  assert.deepEqual(doc.scopes_supported, ['openid', SCOPE]);
  assert.equal(metadataUrl(RESOURCE), 'https://mcp.example.test/.well-known/oauth-protected-resource/mcp');
  assert.equal(metadataUrl('https://x.example'), 'https://x.example/.well-known/oauth-protected-resource');
});

test('no token: 401 with WWW-Authenticate pointing at the metadata', async () => {
  const res = challenge(cfg);
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate')!, /^Bearer resource_metadata="https:\/\/mcp\.example\.test\/\.well-known\/oauth-protected-resource\/mcp"$/);
  assert.equal(await verifyBearer(null, cfg).then((r) => r.ok), false);
});

test('a token minted for this server is accepted and carries the identity', async () => {
  const out = await verifyBearer(await mint(), cfg);
  assert.ok(out.ok);
  assert.equal(out.identity.sub, 'u-123');
  assert.equal(out.identity.email, 'owner@example.test');
  assert.equal(out.identity.emailVerified, true);
  assert.deepEqual(out.identity.scopes, ['openid', SCOPE]);
  assert.equal(out.identity.clientId, 'zq_agent');
});

test('a token for ANOTHER server, another issuer, or the wrong type is refused', async () => {
  for (const [name, token] of [
    ['other aud', await mint({}, { aud: 'https://other.example/mcp' })],
    ['other iss', await mint({}, { iss: 'https://evil.example' })],
    ['id token, not access token', await mint({}, { typ: 'JWT' })],
    ['garbage', 'eyJ.not.a.token'],
  ] as const) {
    const out = await verifyBearer(token, cfg);
    assert.equal(out.ok, false, name);
    if (!out.ok) { assert.equal(out.status, 401, name); assert.equal(out.error, 'invalid_token', name); }
  }
});

test('a real token without the scope is 403 insufficient_scope, with the scope named', async () => {
  const out = await verifyBearer(await mint({ scope: 'openid' }), cfg);
  assert.equal(out.ok, false);
  if (out.ok) return;
  assert.equal(out.status, 403);
  assert.equal(out.error, 'insufficient_scope');
  const res = challenge(cfg, out);
  assert.equal(res.status, 403);
  assert.match(res.headers.get('www-authenticate')!, /error="insufficient_scope"/);
  assert.match(res.headers.get('www-authenticate')!, /scope="mcp:tools"/);
});

test('bearerToken reads the header and nothing else', () => {
  assert.equal(bearerToken(new Request('https://x', { headers: { authorization: 'Bearer abc.def.ghi' } })), 'abc.def.ghi');
  assert.equal(bearerToken(new Request('https://x', { headers: { authorization: 'Basic abc' } })), null);
  assert.equal(bearerToken(new Request('https://x')), null);
});

// ------------------------------------------------------- the Worker itself --

// auth.ts reads keys from the issuer's /jwks; pin the local set for this issuer.
useKeys(ISSUER, keys);
const env = { ZAPQR_ISSUER: ISSUER, RESOURCE: RESOURCE };

async function rpc(token: string | null, body: unknown) {
  const req = new Request(RESOURCE, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-06-18',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return worker.fetch(req, env);
}

test('the Worker: metadata, home page, 401 on /mcp without a token', async () => {
  const prm = await worker.fetch(new Request('https://mcp.example.test/.well-known/oauth-protected-resource/mcp'), env);
  assert.equal(prm.status, 200);
  assert.deepEqual((await prm.json() as { authorization_servers: string[] }).authorization_servers, [ISSUER]);
  const root = await worker.fetch(new Request('https://mcp.example.test/.well-known/oauth-protected-resource'), env);
  assert.equal(root.status, 200);
  const home = await worker.fetch(new Request('https://mcp.example.test/'), env);
  assert.equal(home.status, 200);
  assert.match(await home.text(), /MCP server/);
  const res = await rpc(null, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate') ?? '', /resource_metadata=/);
  assert.equal(res.headers.get('access-control-expose-headers')?.includes('www-authenticate'), true);
  const nope = await worker.fetch(new Request('https://mcp.example.test/other'), env);
  assert.equal(nope.status, 404);
});

test('the Worker: a token for another server is refused before MCP is touched', async () => {
  const res = await rpc(await mint({}, { aud: 'https://other.example/mcp' }), { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate') ?? '', /error="invalid_token"/);
});

test('the Worker: initialize → tools/list → tools/call, identity on the call', async () => {
  const token = await mint();
  const init = await rpc(token, {
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } },
  });
  if (init.status !== 200) assert.fail(`initialize ${init.status}: ${await init.text()}`);
  const initBody = await init.json() as { result: { serverInfo: { name: string }, capabilities: { tools?: unknown } } };
  assert.equal(initBody.result.serverInfo.name, 'zapqr-mcp-starter');
  assert.ok(initBody.result.capabilities.tools, 'advertises tools');

  const list = await rpc(token, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  assert.equal(list.status, 200);
  const tools = (await list.json() as { result: { tools: { name: string }[] } }).result.tools.map((t) => t.name).sort();
  assert.deepEqual(tools, ['echo', 'whoami']);

  const who = await rpc(token, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'whoami', arguments: {} } });
  assert.equal(who.status, 200);
  const whoText = (await who.json() as { result: { content: { text: string }[] } }).result.content[0].text;
  assert.match(whoText, /sub: u-123/);
  assert.match(whoText, /owner@example\.test \(verified by ZapQR\)/);
  assert.match(whoText, /scopes: openid mcp:tools/);

  const echo = await rpc(token, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'echo', arguments: { text: 'hi' } } });
  const echoText = (await echo.json() as { result: { content: { text: string }[] } }).result.content[0].text;
  assert.equal(echoText, 'hi\n— owner@example.test');
});
