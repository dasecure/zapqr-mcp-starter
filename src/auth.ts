// The whole of "auth for your MCP server", in one file.
//
// Per the MCP authorization spec (2026-07-28) an MCP server is an OAuth 2.1
// RESOURCE SERVER. It never signs anyone in. It does three things:
//
//   1. publishes RFC 9728 metadata saying which authorization server to use
//      (protectedResourceMetadata),
//   2. answers an unauthenticated request with 401 + a WWW-Authenticate header
//      that points at that metadata (challenge),
//   3. verifies every bearer token's signature, issuer, expiry and — the one
//      that matters most — that its audience (`aud`) is THIS server, so a
//      token minted for some other MCP server is refused (verifyBearer).
//
// ZapQR mints the token: a JWT signed with the key at <issuer>/jwks, `iss` =
// the issuer, `aud` = the resource you registered at auth.zapqr.ai/account/agents,
// `sub` = the person's stable account id, `email` + `email_verified`, and
// `scope` = what they approved on the consent screen.

import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';

export const DEFAULT_ISSUER = 'https://auth.zapqr.ai';
export const SCOPE = 'mcp:tools';

export interface AuthConfig {
  /** The authorization server. Defaults to https://auth.zapqr.ai. */
  issuer: string;
  /** This server's identifier — the exact string registered on ZapQR (the JWT `aud`). */
  resource: string;
  /** Key resolver; defaults to the issuer's JWKS. Injected by tests. */
  keys?: JWTVerifyGetKey;
}

export interface Identity {
  sub: string;
  email?: string;
  emailVerified: boolean;
  scopes: string[];
  clientId?: string;
  expiresAt?: number;
  token: string;
}

export type VerifyResult =
  | { ok: true; identity: Identity }
  | { ok: false; status: 401 | 403; error: 'invalid_token' | 'insufficient_scope'; description: string };

const jwksCache = new Map<string, JWTVerifyGetKey>();

/** One remote JWKS per issuer, cached across requests in this isolate. */
export function keysFor(issuer: string): JWTVerifyGetKey {
  let keys = jwksCache.get(issuer);
  if (!keys) {
    keys = createRemoteJWKSet(new URL('/jwks', issuer), { cooldownDuration: 30_000, cacheMaxAge: 600_000 });
    jwksCache.set(issuer, keys);
  }
  return keys;
}

/** Pin the key set for an issuer — tests, or an air-gapped deployment that ships the JWKS. */
export function useKeys(issuer: string, keys: JWTVerifyGetKey): void {
  jwksCache.set(issuer, keys);
}

/** RFC 9728 — what to serve at /.well-known/oauth-protected-resource. */
export function protectedResourceMetadata(cfg: Pick<AuthConfig, 'issuer' | 'resource'>) {
  return {
    resource: cfg.resource,
    authorization_servers: [cfg.issuer],
    scopes_supported: ['openid', SCOPE],
    bearer_methods_supported: ['header'],
    resource_name: 'MCP server secured by ZapQR',
  };
}

/** Where the metadata lives, given the resource URL. RFC 9728 §3: path-inserted; the root form is served too. */
export function metadataUrl(resource: string): string {
  const u = new URL(resource);
  const path = u.pathname.replace(/\/+$/, '');
  return `${u.origin}/.well-known/oauth-protected-resource${path}`;
}

/**
 * The 401 / 403 the spec requires, with the header an MCP client parses to
 * find the authorization server. `error` and `error_description` follow
 * RFC 6750; `resource_metadata` follows RFC 9728 §5.1.
 */
export function challenge(cfg: Pick<AuthConfig, 'resource'>, failure?: Extract<VerifyResult, { ok: false }>): Response {
  const parts = [`resource_metadata="${metadataUrl(cfg.resource)}"`];
  if (failure) {
    parts.push(`error="${failure.error}"`, `error_description="${failure.description.replace(/"/g, "'")}"`);
    if (failure.error === 'insufficient_scope') parts.push(`scope="${SCOPE}"`);
  }
  const status = failure?.status ?? 401;
  return new Response(JSON.stringify({ error: failure?.error ?? 'unauthorized', error_description: failure?.description ?? 'Bearer token required.' }), {
    status,
    headers: {
      'content-type': 'application/json',
      'www-authenticate': `Bearer ${parts.join(', ')}`,
      'cache-control': 'no-store',
    },
  });
}

/** The bearer token from a request, or null. */
export function bearerToken(request: Request): string | null {
  const h = request.headers.get('authorization') ?? '';
  const m = /^Bearer\s+([A-Za-z0-9._~+/=-]+)$/i.exec(h.trim());
  return m ? m[1] : null;
}

/**
 * Verify a bearer token. Every failure is a 401 invalid_token except a token
 * that is real but lacks the scope, which is a 403 insufficient_scope — the
 * distinction tells the client whether to get a NEW token or ask for MORE.
 */
export async function verifyBearer(token: string | null, cfg: AuthConfig): Promise<VerifyResult> {
  if (!token) return { ok: false, status: 401, error: 'invalid_token', description: 'Bearer token required.' };
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, cfg.keys ?? keysFor(cfg.issuer), {
      issuer: cfg.issuer,
      audience: cfg.resource,
      algorithms: ['RS256'],
      typ: 'at+jwt',
      clockTolerance: 30,
    }));
  } catch (e) {
    return { ok: false, status: 401, error: 'invalid_token', description: (e as Error)?.message ?? 'Token rejected.' };
  }
  if (typeof payload.sub !== 'string' || !payload.sub) {
    return { ok: false, status: 401, error: 'invalid_token', description: 'Token has no subject.' };
  }
  const scopes = String(payload.scope ?? '').split(' ').filter(Boolean);
  if (!scopes.includes(SCOPE)) {
    return { ok: false, status: 403, error: 'insufficient_scope', description: `Token lacks the ${SCOPE} scope.` };
  }
  return {
    ok: true,
    identity: {
      sub: payload.sub,
      email: typeof payload.email === 'string' ? payload.email : undefined,
      emailVerified: payload.email_verified === true,
      scopes,
      clientId: typeof payload.client_id === 'string' ? payload.client_id : (typeof payload.azp === 'string' ? payload.azp : undefined),
      expiresAt: payload.exp,
      token,
    },
  };
}
