import type { Queryable } from '../types.js';

/**
 * An `auth_domains` row — one of a tenant's org-bound sign-in IdPs. A tenant
 * has 0..N of these; the router lists them for a tenant. OIDC rows are driven
 * by the dedicated `@smplcty/auth/oidc` handler (not the generic OTP path);
 * `displayName` is the chooser-button label when a tenant has more than one.
 *
 * @typeParam TParams - Shape of `integration_params`. Defaults to an open
 *   record; narrow it in a handler.
 */
export interface AuthDomain<TParams = Record<string, unknown>> {
  readonly authDomainId: number;
  readonly tenantId: number;
  /** Button label when the tenant has several IdPs (e.g. "Microsoft"). */
  readonly displayName: string;
  /** Selects the handler — e.g. 'oidc'. */
  readonly integrationType: string;
  /** Provider config. Handler-specific. */
  readonly integrationParams: TParams;
}

/**
 * A user verified by a method handler, ready for `createSession`.
 */
export interface ResolvedUser {
  readonly userId: number;
  readonly userCommunicationMethodId: number;
}

/**
 * Result of a user-bound handler's `initiate` phase.
 */
export type MethodInitiateResult = { readonly otpSent: true };

/**
 * Context handed to a user-bound (OTP) handler's `initiate`.
 */
export interface MethodInitiateContext {
  /** A connection or pool the handler may query (e.g. to find the user). */
  readonly db: Queryable;
  /** The identifier the user entered (email/phone). */
  readonly identifier: string;
}

/**
 * Context handed to a user-bound handler's `complete`. Adds the submitted OTP.
 */
export interface MethodCompleteContext extends MethodInitiateContext {
  readonly credential: string;
}

/**
 * A pluggable **user-bound** (OTP-style) two-phase method: `initiate` sends a
 * code, `complete` verifies it. Injected into the router as `otpHandler`. Auth
 * core depends on no protocol library. (Org-bound OIDC is handled separately by
 * `@smplcty/auth/oidc`'s richer `authorize`/`callback` shape, not this.)
 */
export interface MethodHandler {
  initiate(ctx: MethodInitiateContext): Promise<MethodInitiateResult>;
  complete(ctx: MethodCompleteContext): Promise<ResolvedUser>;
}

/**
 * Options for {@link createMethodRouter}.
 */
export interface MethodRouterOptions {
  /** Used to look up tenants and their `auth_domains`. */
  db: Queryable;
  /** The user-bound OTP handler (e.g. a `TwilioVerifyHandler`). Omit it for an
   *  SSO-only product. */
  otpHandler?: MethodHandler;
}

/**
 * The sign-in methods available for a tenant — what the app renders.
 */
export interface SignInOptions {
  readonly tenantId: number;
  /** The tenant's org-bound IdPs. Zero ⇒ OTP only; one ⇒ straight redirect;
   *  several ⇒ a chooser. **May mix `integrationType`s** — the consumer must
   *  branch on `integrationType` and only render a start route for protocols it
   *  can drive (today only `'oidc'` has a shipped handler: `@smplcty/auth/oidc`).
   *  This list is discovery ("here are your IdPs"), not a guarantee every row is
   *  startable. */
  readonly authDomains: readonly AuthDomain[];
  /** Whether to offer OTP: an `otpHandler` is configured. (Addresses at an
   *  SSO-required verified domain are still refused, per address.) */
  readonly otpAllowed: boolean;
}

/**
 * Tenant-centric sign-in **discovery + the user-bound OTP path**. Discovery is
 * by sub-domain → tenant (the app parses the Host to a slug). OIDC completion
 * is not routed here — resolve the tenant's OIDC `auth_domains` via
 * `signInOptions`, then drive `@smplcty/auth/oidc`'s handler directly.
 */
export interface MethodRouter {
  /** The sign-in methods for the tenant owning `tenantSlug`, or null if no
   *  such (live) tenant. */
  signInOptions(input: { tenantSlug: string }): Promise<SignInOptions | null>;
  /** User-bound (OTP) phase 1. Throws {@link OtpNotAllowedError} when no OTP
   *  handler is configured, {@link SsoRequiredError} for an address at an
   *  SSO-required verified domain. */
  initiateOtp(input: { identifier: string }): Promise<MethodInitiateResult>;
  /** User-bound (OTP) phase 2. Throws {@link OtpNotAllowedError} when no OTP
   *  handler is configured, {@link SsoRequiredError} when the signed-in user has
   *  an address at an SSO-required verified domain. */
  completeOtp(input: { identifier: string; credential: string }): Promise<ResolvedUser>;
}
