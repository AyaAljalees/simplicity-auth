import type { Pool } from 'pg';
import type { GeoLocation, Logger, ScopeHook } from '../types.js';
import type { IdentifierKind, MethodHandler, OtpHandlers, ResolvedUser } from '../methods/types.js';
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
  /** Where to send the browser when an OIDC sign-in fails at start or callback, with the
   *  error code appended as `?error=<CODE>`. Must be a path on this site;
   *  `createAuthHandlers` throws otherwise. Omit it to answer those failures with JSON. */
  signInErrorPath?: string;
  /** Called when an OIDC sign-in through a known auth domain fails, at start or
   *  callback, before the failure is answered, so the app can show that
   *  provider's admins why. Not called when no auth domain can be named: a
   *  callback without a valid login-state cookie, or an unknown auth domain. A
   *  hook that throws is logged and ignored; the person still gets the answer. */
  onSignInFailure?: (failure: SignInFailure) => void | Promise<void>;
  /** The user-bound code handler: one for every identifier (e.g. `twilioVerifyHandler`),
   *  or one per kind, `{ email, phone }`. Omit for SSO-only. */
  otpHandler?: MethodHandler | OtpHandlers;
  /** Refuse a phone, or an address at another domain, whose owner must use SSO, as
   *  `403 SSO_REQUIRED` instead of a silent "code sent". See `MethodRouterOptions`. */
  revealSsoRequiredUsers?: boolean;
  /** Answer an email or phone that no account uses as `404 UNKNOWN_IDENTIFIER`, and a
   *  failed send as `503 DELIVERY_UNAVAILABLE`, instead of a silent "code sent".
   *  Rate-limit `otp/initiate` per client before turning this on. See `MethodRouterOptions`. */
  revealUnknownIdentifiers?: boolean;
  /** The app's own rules around a sign-in. See {@link SignInHooks}. */
  signIn?: SignInHooks;
  /** The org-bound OIDC handler (`oidcHandler` from `@smplcty/auth/oidc`). Omit if the app has no OIDC. */
  oidc?: OidcHandler;
  /** App-owned intra-tenant scope hook, applied by `withRequestSession` / the session endpoint. */
  scope?: ScopeHook;
  logger?: Logger;
  /** Derive IP/geo for the `sessions` row from the request. */
  sessionMeta?: (request: Request) => RequestSessionMeta | undefined;
}

/** A failed OIDC sign-in, for {@link AuthHttpConfig.onSignInFailure}. */
export interface SignInFailure {
  /** The code the person's answer carries (`?error=` with `signInErrorPath`). */
  code: string;
  /** The auth domain the attempt went through. */
  authDomainId: number;
  /** Why, for that provider's admins: the identity provider's own error when it
   *  sent one, else the library's. Never a credential or token. */
  detail: string;
  /** What was thrown, for the app's own logs. */
  error: unknown;
  request: Request;
}

/** How the person proved who they are. */
export type SignInMethod = 'otp' | 'oidc';

/**
 * The app's own rules around a sign-in, run inside the HTTP tier. Refuse by
 * throwing `SignInRefusedError` with the message to show. A refusal never
 * creates a session.
 */
export interface SignInHooks {
  /** Before a code is sent (`initiate`) or checked (`complete`). Return the
   *  identifier to use, e.g. a normalized phone number, or nothing to keep it.
   *  Throw to refuse before anything is sent, e.g. a channel the app has
   *  switched off. */
  beforeOtp?(ctx: {
    request: Request;
    identifier: string;
    kind: IdentifierKind;
    step: 'initiate' | 'complete';
  }): string | void | Promise<string | void>;
  /** After the person is verified, by code or by an IdP, and before a session
   *  exists. Throw to refuse, e.g. a user with no access to an active workspace. */
  beforeSession?(ctx: { request: Request; user: ResolvedUser; method: SignInMethod }): void | Promise<void>;
  /** After the session is created, e.g. to record login history. A throw is
   *  logged and never fails the sign-in, which has already happened. */
  afterSignIn?(ctx: { request: Request; user: ResolvedUser; method: SignInMethod }): void | Promise<void>;
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
