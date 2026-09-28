# Auth for your MCP server in 5 minutes

An MCP server on Cloudflare Workers where **Sign in with ZapQR** is the authorization server. People connect Claude, Cursor or VS Code to your tools by signing in with a passkey or a scan from their phone. No passwords. No API keys to hand out. No user table to run.

```
npx degit dasecure/zapqr-mcp-starter my-mcp && cd my-mcp
npm install
npx wrangler deploy          # → https://my-mcp.<you>.workers.dev
```

Then register `https://my-mcp.<you>.workers.dev/mcp` at **[auth.zapqr.ai/account/agents](https://auth.zapqr.ai/account/agents)** and add that URL to Claude as a remote MCP server. That's the five minutes.

---

## Why this works

The [MCP authorization spec](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) (2026-07-28) makes your MCP server an OAuth 2.1 **resource server**. It never signs anyone in. It does exactly three things, and this repo does all three in [`src/auth.ts`](src/auth.ts):

| # | Your server must… | Where |
|---|---|---|
| 1 | Publish **RFC 9728** metadata naming its authorization server | `GET /.well-known/oauth-protected-resource` |
| 2 | Answer an unauthenticated request with **401 + `WWW-Authenticate`** pointing at that metadata | `challenge()` |
| 3 | Verify each bearer token's signature, issuer, expiry and — the one that matters — that its **`aud` is this server** | `verifyBearer()` |

Everything else happens between the MCP client and ZapQR: the client reads your metadata, finds `https://auth.zapqr.ai`, registers itself (RFC 7591, or by presenting a Client ID Metadata Document), runs the sign-in with PKCE and an RFC 8707 `resource=` naming your server, and comes back with a JWT. ZapQR shows the person a consent screen that reads **"Connect Claude to *your server* (your-host)?"**

```
Claude ──POST /mcp (no token)──▶ your Worker ──401 WWW-Authenticate: Bearer resource_metadata="…"──▶ Claude
Claude ──GET /.well-known/oauth-protected-resource──▶ { authorization_servers: ["https://auth.zapqr.ai"] }
Claude ──discovery, register, /auth?resource=<your URL>──▶ auth.zapqr.ai ──passkey / phone / consent──▶ person
Claude ◀── JWT { iss: auth.zapqr.ai, aud: <your URL>, sub, email, scope: "openid mcp:tools" } ──
Claude ──POST /mcp  Authorization: Bearer <JWT>──▶ your Worker ──verify against auth.zapqr.ai/jwks──▶ tools/call
```

## What's in the token

Every request to `/mcp` arrives with a verified identity on `authInfo.extra.identity`:

```ts
{ sub: 'a3f9…',                 // stable account id — key your data on this
  email: 'ana@example.com',     // verified by ZapQR when emailVerified is true
  emailVerified: true,
  scopes: ['openid', 'mcp:tools'],
  clientId: 'zq_…',             // which agent (Claude, Cursor, …) is calling
  expiresAt: 1790000000 }
```

Tokens last an hour; the client refreshes them without bothering the person.

## The three strings

After you register on `/account/agents` you get exactly three strings. The Worker already knows two of them and derives the third from the request, so with the defaults there is nothing to configure. Set them in `wrangler.toml` only if you need to:

| Var | Default | When to set |
|---|---|---|
| `RESOURCE` | `<origin>/mcp` of the incoming request | You serve the same Worker on several hostnames and registered one |
| `ZAPQR_ISSUER` | `https://auth.zapqr.ai` | You self-host the ZapQR IdP |
| scope | `mcp:tools` | Never — it's the one scope every registered server carries |

**The `RESOURCE` string must match what you registered, character for character.** Trailing slash, port, path — all of it. It's an identifier, not a URL anyone fetches.

## The tools it ships with

[`src/tools.ts`](src/tools.ts) registers five, and they are there to show the identity doing work, not to be kept:

| Tool | What it proves |
|---|---|
| `whoami` | the verified identity made it through: `sub`, `email (verified by ZapQR)`, scopes, which agent |
| `echo` | the tool round trip |
| `remember` / `recall` / `forget` | **per-person isolation** — notes live in Cloudflare KV under `sub:` and two people connecting the same server each see only their own. No login form, no API key, no user table; the isolation is a key prefix |

`remember`/`recall` need a KV namespace: `npx wrangler kv namespace create NOTES`, paste the id into `wrangler.toml`. Without it the three tools answer with a clear error and everything else works.

## Add your own

Each handler gets `extra.authInfo.extra.identity` — the same person on every call, verified on every request, no session to keep.

```ts
server.registerTool('list_orders', {
  description: 'Orders for the signed-in customer',
  inputSchema: { since: z.string().optional() },
}, async ({ since }, extra) => {
  const { sub } = extra.authInfo!.extra!.identity as Identity;
  const rows = await env.DB.prepare('select * from orders where customer = ?').bind(sub).all();
  return { content: [{ type: 'text', text: JSON.stringify(rows.results) }] };
});
```

## Test it

```
npm test                 # 10 tests: token minted like ZapQR mints it → full MCP round trip + per-person isolation, no network
npm run check            # tsc
npx wrangler dev         # local, then add http://localhost:8787/mcp to Claude Desktop*
```

\* Local dev works with a real ZapQR sign-in as long as you registered `http://localhost:8787/mcp`… which you can't — audiences must be https. For local work, mint a test token the way [`test/worker.test.ts`](test/worker.test.ts) does and pin the key with `useKeys()`, or deploy to a `workers.dev` preview and test there. Five minutes either way.

## Connect it

**Claude** (web / desktop): Settings → Connectors → *Add custom connector* → paste `https://my-mcp.<you>.workers.dev/mcp`. Claude finds ZapQR from your metadata, registers itself and opens the sign-in.

**Cursor / VS Code / Claude Code**: add a remote server with that URL; each of these implements the same discovery.

**Your own agent**: any MCP client that implements the 2025-06-18 or later authorization flow. If yours only takes a URL and a static headers map, it can't run the flow — put an MCP-aware client in front of it.

## See a finished one

ZapQR runs its own MCP server, built the same way this starter is: **`https://auth.zapqr.ai/mcp`**. Connect it (Claude → Settings → Connectors → *Add custom connector*) and you'll see the whole flow — discovery, sign-in, consent, a tool call — before you write a line.

It exposes your ZapQR account as tools an agent may use as you, behind two scopes:

| Scope | Tools |
|---|---|
| `zapqr:sessions` — see and sign out your signed-in sessions | `list_sessions`, `sign_out_session {id}`, `sign_out_everywhere_else {confirm: true}` |
| `zapqr:connections` — see and disconnect the sites and agents connected to your account | `list_connections`, `disconnect {id}` |
| *(none)* | `whoami` |

`list_sessions` marks the session that authorized the agent; `sign_out_everywhere_else` keeps that one and pushes a security notification. Disconnect the agent on [your account page](https://auth.zapqr.ai/account) and its next call is refused — the same lever your users will have over the server you build here.

## What this is not

- **Not an API key.** A token is bound to one person, one agent, one server, and expires. If you want a long-lived machine credential, that's a different product.
- **Not a session.** The Worker is stateless (`sessionIdGenerator: undefined`), so any isolate answers any request. Add a Durable Object if a tool needs conversation state.
- **Not a scope system.** `mcp:tools` means "may use this server as me". Authorization *inside* your tools — who may see which order — is yours, keyed on `sub`.

## Files

```
src/index.ts   routes: metadata, home page, the /mcp gate, CORS
src/auth.ts    RFC 9728 metadata · 401/403 challenge · JWT verification (jose) — the whole integration
src/tools.ts   your tools (whoami, echo, remember/recall/forget on KV)
test/          token minted like ZapQR mints it → 401 → verify → initialize → tools/list → tools/call
wrangler.toml  name, compatibility date, the two optional vars, the NOTES KV binding
```

Dependencies: `@modelcontextprotocol/sdk` (the protocol), `jose` (JWT + JWKS), `zod` (tool input schemas). Nothing else.

## About ZapQR

[ZapQR](https://zapqr.ai) is a passwordless identity provider: passkeys first, scan-a-QR-approve-on-your-phone for screens that can't hold credentials, push-to-approve as the third path. It speaks OpenID Connect to websites, RFC 8628 device flow to hardware, and — with this starter — the MCP authorization spec to agents. Same account, same phone, every surface.

Guide with screenshots: **[zapqr.ai/mcp](https://zapqr.ai/mcp)**. Questions: [vincent@dasecure.com](mailto:vincent@dasecure.com).

MIT © DaSecure Solutions LLC
