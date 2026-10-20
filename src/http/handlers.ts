import type { Pool, PoolClient } from 'pg';
import { createSession } from '../create-session.js';
import { revokeSession } from '../revoke-session.js';
import { withSession } from '../with-session.js';
import { createMethodRouter } from '../methods/router.js';
import {
  AuthError,
  InvalidInputError,
  RoleNotHeldError,
  SessionExpiredError,
  SessionNotFoundError,
} from '../errors.js';
import {
  EmailDomainNotVerifiedError,
  OtpNotAllowedError,
  SsoRequiredError,
  VerificationFailedError,
} from '../methods/errors.js';
import type { AuthDomain, ResolvedUser } from '../methods/types.js';
import type { OidcParams } from '../methods/oidc/index.js';
import type { SessionContext } from '../types.js';
import {
  parseCookies,
  serializeCookie,
  signLoginState,
  verifyLoginState,
  type SerializeCookieOptions,
} from './cookies.js';
import type { AuthHandlers, AuthHttpConfig } from './types.js';

const DEFAULT_SESSION_TTL = '30 days';
const DEFAULT_LOGIN_STATE_TTL = 600;

const SELECT_TENANT_ID = `SELECT tenant_id AS "tenantId" FROM tenants WHERE slug = $1 AND deleted_at IS NULL LIMIT 1`;

const SELECT_AUTH_DOMAIN = `
  SELECT
    auth_domain_id     AS "authDomainId",
    tenant_id          AS "tenantId",
    display_name       AS "displayName",
    integration_type   AS "integrationType",
    integration_params AS "integrationParams"
  FROM auth_domains
  WHERE auth_domain_id = $1 AND deleted_at IS NULL
  LIMIT 1
`;

/** Extract the raw session token from the `Authorization: Bearer` header or the session cookie. */
export function getSessionToken(request: Request, config: AuthHttpConfig): string | null {
  const auth = request.headers.get('authorization');
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.slice('Bearer '.length).trim();
    if (token) return token;
  }
  const cookies = parseCookies(request.headers.get('cookie'));
  return cookies[config.cookie.name] ?? null;
}

/**
 * Resolve the request's session and run `fn` inside its RLS transaction with
 * the identity GUCs (and the app scope hook) applied. Throws
 * {@link SessionNotFoundError} when no token is present, and whatever
 * `withSession` throws for an invalid/expired session or an unheld role.
 */
export function withRequestSession<TRole extends string = string, T = unknown>(
  request: Request,
  config: AuthHttpConfig,
  fn: (client: PoolClient, ctx: SessionContext<TRole>) => Promise<T>,
  opts: { roleName?: TRole } = {},
): Promise<T> {
  const token = getSessionToken(request, config);
  if (!token) return Promise.reject(new SessionNotFoundError('No session token on request'));
  return withSession<TRole, T>(config.pool, { token, roleName: opts.roleName }, fn, {
    scope: config.scope,
    logger: config.logger,
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { location } });
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  try {
    const body = await request.json();
    if (body === null || typeof body !== 'object') throw new InvalidInputError('request body must be a JSON object');
    return body as Record<string, unknown>;
  } catch (err) {
    if (err instanceof AuthError) throw err;
    throw new InvalidInputError('request body must be valid JSON');
  }
}

function requireString(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new InvalidInputError(`${key} must be a non-empty string`);
  }
  return value;
}

/** Map a thrown auth error to an HTTP response. Unknown errors become an opaque 500. */
function toErrorResponse(err: unknown): Response {
  if (err instanceof InvalidInputError) return json({ error: err.message, code: err.code }, 400);
  if (err instanceof OtpNotAllowedError) return json({ error: 'OTP sign-in is not allowed', code: err.code }, 403);
  if (err instanceof SsoRequiredError) return json({ error: 'Sign in with your organization', code: err.code }, 403);
  if (err instanceof EmailDomainNotVerifiedError) {
    return json({ error: 'This organization has not verified that email domain', code: err.code }, 403);
  }
  if (err instanceof VerificationFailedError) return json({ error: 'Verification failed', code: err.code }, 401);
  if (err instanceof RoleNotHeldError) return json({ error: 'Role not held', code: err.code }, 403);
  if (err instanceof SessionExpiredError) return json({ error: 'Session expired', code: err.code }, 401);
  if (err instanceof SessionNotFoundError) return json({ error: 'Not authenticated', code: err.code }, 401);
  return json({ error: 'Internal error' }, 500);
}

const RETURN_TO_PROBE_ORIGIN = 'https://return-to.invalid';

/**
 * The same-origin path a browser would reach from `raw`, or undefined when it
 * would leave the site (open-redirect guard). Browsers strip leading spaces and
 * control characters, drop tab, CR and LF, and resolve dot segments and
 * backslashes before reading the host, so the check runs on the parsed URL, not
 * the raw string.
 */
function sanitizeReturnTo(raw: string | null | undefined): string | undefined {
  // Root-relative once the parser strips leading C0 controls and spaces.
  if (!raw || !/^[\0- ]*\//.test(raw)) return undefined;
  let url: URL;
  try {
    url = new URL(raw, RETURN_TO_PROBE_ORIGIN);
  } catch {
    return undefined;
  }
  const path = url.pathname + url.search + url.hash;
  // The parser has already turned backslashes into slashes, but resolving a dot
  // segment (`/.//evil.com`) can still leave a path that reads as `//host`.
  return url.origin === RETURN_TO_PROBE_ORIGIN && !path.startsWith('//') ? path : undefined;
}

export function createAuthHandlers(config: AuthHttpConfig): AuthHandlers {
  const returnToDefault = sanitizeReturnTo(config.returnToDefault ?? '/');
  if (!returnToDefault) {
    throw new Error(`returnToDefault must be a path on this site, got ${JSON.stringify(config.returnToDefault)}`);
  }
  const pool: Pool = config.pool;
  const router = createMethodRouter({ db: pool, otpHandler: config.otpHandler });
  const sessionTtl = config.sessionTtl ?? DEFAULT_SESSION_TTL;
  const loginStateTtl = config.loginStateTtlSeconds ?? DEFAULT_LOGIN_STATE_TTL;
  const loginStateCookieName = `${config.cookie.name}_oidc`;

  function sessionCookieOptions(maxAge: number): SerializeCookieOptions {
    return {
      domain: config.cookie.domain,
      path: config.cookie.path ?? '/',
      sameSite: config.cookie.sameSite ?? 'lax',
      secure: config.cookie.secure ?? true,
      httpOnly: true,
      maxAge,
    };
  }

  async function resolveTenantId(request: Request): Promise<number | null> {
    const slug = await config.tenantSlugFromRequest(request);
    if (!slug) return null;
    const { rows } = await pool.query<{ tenantId: string | number }>(SELECT_TENANT_ID, [slug]);
    const id = rows[0]?.tenantId;
    // bigint arrives from pg as a string; downstream validators want a number.
    return id == null ? null : Number(id);
  }

  /** Create a session for the verified user and return the Set-Cookie value. */
  async function mintSessionCookie(request: Request, user: ResolvedUser): Promise<string> {
    const meta = config.sessionMeta?.(request);
    const session = await createSession(pool, {
      userCommunicationMethodId: user.userCommunicationMethodId,
      ttl: sessionTtl,
      ip: meta?.ip,
      geo: meta?.geo,
    });
    // createSession owns the authoritative server-side expiry; the cookie
    // Max-Age is only a client hint (default 30 days).
    return serializeCookie(
      config.cookie.name,
      session.token,
      sessionCookieOptions(config.cookie.maxAgeSeconds ?? 60 * 60 * 24 * 30),
    );
  }

  const handlers: AuthHandlers = {
    async signInOptions(request) {
      try {
        const slug = await config.tenantSlugFromRequest(request);
        if (!slug) return json({ error: 'tenant could not be resolved from the request' }, 400);
        const opts = await router.signInOptions({ tenantSlug: slug });
        if (!opts) return json({ error: 'unknown tenant' }, 404);
        return json({
          tenantId: opts.tenantId,
          otpAllowed: opts.otpAllowed,
          authDomains: opts.authDomains.map((d) => ({
            authDomainId: d.authDomainId,
            displayName: d.displayName,
            integrationType: d.integrationType,
          })),
        });
      } catch (err) {
        return toErrorResponse(err);
      }
    },

    async otpInitiate(request) {
      try {
        // Sign-in happens on a tenant's sub-domain; an unknown one is a 404.
        if ((await resolveTenantId(request)) === null) return json({ error: 'unknown tenant' }, 404);
        const body = await readJson(request);
        const identifier = requireString(body, 'identifier');
        const result = await router.initiateOtp({ identifier });
        return json(result);
      } catch (err) {
        return toErrorResponse(err);
      }
    },

    async otpComplete(request) {
      try {
        if ((await resolveTenantId(request)) === null) return json({ error: 'unknown tenant' }, 404);
        const body = await readJson(request);
        const identifier = requireString(body, 'identifier');
        const credential = requireString(body, 'credential');
        const user = await router.completeOtp({ identifier, credential });
        const cookie = await mintSessionCookie(request, user);
        const returnTo = sanitizeReturnTo(typeof body.returnTo === 'string' ? body.returnTo : undefined);
        const res = json({ ok: true, returnTo: returnTo ?? returnToDefault });
        res.headers.append('set-cookie', cookie);
        return res;
      } catch (err) {
        return toErrorResponse(err);
      }
    },

    async oidcStart(request) {
      try {
        if (!config.oidc) return json({ error: 'OIDC is not configured' }, 404);
        const url = new URL(request.url);
        const idRaw = url.searchParams.get('authDomainId');
        const authDomainId = idRaw ? Number(idRaw) : NaN;
        if (!Number.isInteger(authDomainId) || authDomainId <= 0) {
          throw new InvalidInputError('authDomainId query parameter must be a positive integer');
        }
        const authDomain = await getAuthDomain(pool, authDomainId);
        if (!authDomain) return json({ error: 'unknown auth domain' }, 404);
        const { redirectUrl, loginState } = await config.oidc.initiate(authDomain);
        const returnTo = sanitizeReturnTo(url.searchParams.get('returnTo'));
        const stateToken = await signLoginState(
          { authDomainId, ...loginState, ...(returnTo ? { returnTo } : {}) },
          config.loginStateSecret,
        );
        const res = redirect(redirectUrl);
        res.headers.append(
          'set-cookie',
          serializeCookie(loginStateCookieName, stateToken, {
            ...sessionCookieOptions(loginStateTtl),
            // Lax so the cookie is sent on the top-level GET redirect back from the IdP.
            sameSite: 'lax',
          }),
        );
        return res;
      } catch (err) {
        return toErrorResponse(err);
      }
    },

    async oidcCallback(request) {
      try {
        if (!config.oidc) return json({ error: 'OIDC is not configured' }, 404);
        const cookies = parseCookies(request.headers.get('cookie'));
        const loginState = await verifyLoginState(
          cookies[loginStateCookieName],
          config.loginStateSecret,
          loginStateTtl,
        );
        if (!loginState) return json({ error: 'missing or invalid login state' }, 400);
        const authDomain = await getAuthDomain(pool, loginState.authDomainId);
        if (!authDomain) return json({ error: 'unknown auth domain' }, 404);
        const user = await config.oidc.complete({
          db: pool,
          authDomain,
          callbackUrl: request.url,
          loginState: { state: loginState.state, nonce: loginState.nonce, codeVerifier: loginState.codeVerifier },
        });
        const cookie = await mintSessionCookie(request, user);
        const res = redirect(sanitizeReturnTo(loginState.returnTo) ?? returnToDefault);
        res.headers.append('set-cookie', cookie);
        // Clear the one-time login-state cookie.
        res.headers.append('set-cookie', serializeCookie(loginStateCookieName, '', sessionCookieOptions(0)));
        return res;
      } catch (err) {
        return toErrorResponse(err);
      }
    },

    async signOut(request) {
      try {
        const token = getSessionToken(request, config);
        if (token) await revokeSession(pool, token);
        const res = json({ ok: true });
        res.headers.append('set-cookie', serializeCookie(config.cookie.name, '', sessionCookieOptions(0)));
        return res;
      } catch (err) {
        return toErrorResponse(err);
      }
    },

    async session(request) {
      try {
        const ctx = await withRequestSession(request, config, async (_client, ctx) => ctx);
        return json({ authenticated: true, ...ctx });
      } catch (err) {
        return toErrorResponse(err);
      }
    },

    async handle(request) {
      const { pathname } = new URL(request.url);
      const method = request.method.toUpperCase();
      const at = (suffix: string, verb: string): boolean => method === verb && pathname.endsWith(suffix);

      if (at('/sign-in/options', 'GET')) return handlers.signInOptions(request);
      if (at('/otp/initiate', 'POST')) return handlers.otpInitiate(request);
      if (at('/otp/complete', 'POST')) return handlers.otpComplete(request);
      if (at('/oidc/start', 'GET')) return handlers.oidcStart(request);
      if (at('/oidc/callback', 'GET')) return handlers.oidcCallback(request);
      if (at('/sign-out', 'POST')) return handlers.signOut(request);
      if (at('/session', 'GET')) return handlers.session(request);
      return null;
    },
  };

  return handlers;
}

async function getAuthDomain(pool: Pool, authDomainId: number): Promise<AuthDomain<OidcParams> | null> {
  const { rows } = await pool.query<AuthDomain<OidcParams>>(SELECT_AUTH_DOMAIN, [authDomainId]);
  const row = rows[0];
  if (!row) return null;
  // bigint ids arrive from pg as strings; the AuthDomain shape is `number`.
  return { ...row, authDomainId: Number(row.authDomainId), tenantId: Number(row.tenantId) };
}
