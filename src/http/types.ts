import type { Pool } from 'pg';
import type { GeoLocation, Logger, ScopeHook } from '../types.js';
import type { MethodHandler } from '../methods/types.js';
import type { OidcHandler } from '../methods/oidc/index.js';

/** Session-cookie attributes. The `domain` covers sub-domain sharing (e.g. `.app.example.com`). */
export interface AuthCookieConfig {
  /** Cookie name, e.g. `pn_session`. */
  name: string;
  /** Cookie domain — set to a parent domain to share the session across tenant sub-domains. */
  domain?: string;
  /** Path; defaults to `/`. */
  path?: string;
  /** SameSite; defaults to `lax` (survives the top-level GET redirect back from an IdP). */
  sameSite?: 'lax' | 'strict' | 'none';
  /** Secure; defaults to `true`. Set `false` only for local HTTP dev. */
  secure?: boolean;
  /** Cookie `Max-Age` in seconds; defaults to 30 days. The authoritative expiry is server-side on the session row — this is the browser hint. */
  maxAgeSeconds?: number;
}

/** Per-request session metadata captured at sign-in (stored on the `sessions` row). */
export interface RequestSessionMeta {
  ip?: string;
  geo?: GeoLocation;
}

/**
 * Everything the transport tier needs. The app supplies its pool, cookie
 * policy, a tenant-slug resolver (Host parsing is deployment-specific), and —
 * opt-in — the OTP handler and/or the OIDC handler it constructed (so auth core
 * pulls neither Twilio nor `oauth4webapi`).
 */
export interface AuthHttpConfig {
  /** The RLS pool used for session + method + OIDC operations. */
  pool: Pool;
  cookie: AuthCookieConfig;
  /** Secret used to HMAC-sign the short-lived OIDC login-state cookie. */
  loginStateSecret: string;
  /** Session lifetime as a Postgres interval. Defaults to `'30 days'`. */
  sessionTtl?: string;
  /** Max age of the OIDC login-state cookie, in seconds. Defaults to `600`. */
  loginStateTtlSeconds?: number;
  /** Resolve the tenant slug from the request (e.g. parse the Host sub-domain). */
  tenantSlugFromRequest: (request: Request) => string | null | Promise<string | null>;
  /** Where to send the browser after sign-in when no safe `returnTo` is supplied. Defaults to `'/'`. Must be a path on this site; `createAuthHandlers` throws otherwise. */
  returnToDefault?: string;
  /** The user-bound OTP handler (e.g. `twilioVerifyHandler`). Omit for SSO-only. */
  otpHandler?: MethodHandler;
  /** The org-bound OIDC handler (`oidcHandler` from `@smplcty/auth/oidc`). Omit if the app has no OIDC. */
  oidc?: OidcHandler;
  /** App-owned intra-tenant scope hook, applied by `withRequestSession` / the session endpoint. */
  scope?: ScopeHook;
  logger?: Logger;
  /** Derive IP/geo for the `sessions` row from the request. */
  sessionMeta?: (request: Request) => RequestSessionMeta | undefined;
}

/**
 * The framework-agnostic auth endpoints, each a Web-standard
 * `(Request) => Promise<Response>`. Mount `handle` under a base path (it
 * returns `null` when no auth route matches, so the host can fall through),
 * or wire the individual handlers as explicit routes.
 */
export interface AuthHandlers {
  /** Dispatch any auth route by method + path suffix; `null` if none matches. */
  handle(request: Request): Promise<Response | null>;
  /** `GET …/sign-in/options` — the tenant's IdPs + whether OTP is offered. */
  signInOptions(request: Request): Promise<Response>;
  /** `POST …/otp/initiate` — send an OTP `{ identifier }`. */
  otpInitiate(request: Request): Promise<Response>;
  /** `POST …/otp/complete` — verify `{ identifier, credential }`, mint a session. */
  otpComplete(request: Request): Promise<Response>;
  /** `GET …/oidc/start?authDomainId=&returnTo=` — redirect to the IdP. */
  oidcStart(request: Request): Promise<Response>;
  /** `GET …/oidc/callback` — complete the IdP flow, mint a session, redirect. */
  oidcCallback(request: Request): Promise<Response>;
  /** `POST …/sign-out` — revoke the session and clear the cookie. */
  signOut(request: Request): Promise<Response>;
  /** `GET …/session` — the current identity context, or 401. */
  session(request: Request): Promise<Response>;
}
