import type { Logger, Queryable } from '../types.js';

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
  /** The user `complete` would resolve for `identifier`, or null for an unknown
   *  one, without sending or verifying anything. When present, the router uses
   *  it to send no code to someone `completeOtp` would refuse. */
  resolveUser?(ctx: MethodInitiateContext): Promise<ResolvedUser | null>;
}

/**
 * Options for {@link createMethodRouter}.
 */
/** What an identifier is: one containing `@` is an email, anything else a phone. */
export type IdentifierKind = 'email' | 'phone';

/**
 * Code-sign-in handlers by identifier kind, e.g. `{ email: emailCodeHandler(…),
 * phone: twilioVerifyHandler(…) }`. The router picks one per identifier and
 * keeps every check (including `resolveUser`) for both, so an app needn't write
 * its own dispatcher. A kind with no handler isn't offered.
 */
export interface OtpHandlers {
  email?: MethodHandler;
  phone?: MethodHandler;
}

export interface MethodRouterOptions {
  /** Used to look up tenants and their `auth_domains`. */
  db: Queryable;
  /** The user-bound code handler: one for every identifier, or one per
   *  {@link IdentifierKind}. Omit it for an SSO-only product. */
  otpHandler?: MethodHandler | OtpHandlers;
  /** Refuse an identifier whose owner must use SSO (their phone, or their
   *  address at another domain) with {@link SsoRequiredError}, so the page can
   *  send them to their organization's sign-in. Off by default: the router then
   *  answers as for an unknown identifier, because refusing reveals that the
   *  identifier belongs to someone who must use SSO. */
  revealSsoRequiredUsers?: boolean;
  /** Refuse an email address or phone number that no account uses with
   *  {@link UnknownIdentifierError}, and answer a failed send with
   *  {@link DeliveryUnavailableError}, so the page can tell people what happened.
   *  Off by default, because both reveal who has an account. Turn it on only
   *  when the app rate-limits code sign-in per client: the library can't, and
   *  without it the answer can be scraped. Needs a handler with `resolveUser`
   *  (both shipped handlers have one); without it, unknown identifiers are
   *  answered as when this is off. */
  revealUnknownIdentifiers?: boolean;
  /** Told when code sign-in fails in a way the caller isn't shown in full:
   *  an outage (see {@link DeliveryUnavailableError}), or, with
   *  `revealUnknownIdentifiers` off, any non-`AuthError` failure in the owner's
   *  SSO check or the handler's `initiate`. The identifier and the error's
   *  message are never logged. Defaults to `console`, so an outage is never silent. */
  logger?: Logger;
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
  /** Whether the tenant has a verified email domain that requires SSO: its
   *  people must sign in through {@link authDomains}. */
  readonly ssoRequired: boolean;
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
   *  SSO-required verified domain, and with `revealSsoRequiredUsers` for any
   *  identifier whose owner has one.
   *
   *  Throws {@link DeliveryUnavailableError} when codes can't be sent: by
   *  default, for every identifier of the kind while an outage window is open
   *  (see `OTP_OUTAGE_WINDOW_SECONDS`), and with `revealUnknownIdentifiers`,
   *  whenever the send fails. With `revealUnknownIdentifiers` it also throws
   *  {@link UnknownIdentifierError}. Otherwise, any other failure once the
   *  identifier is resolved (an `AuthError` aside) is reported to `logger` and
   *  answered as an unknown identifier is. */
  initiateOtp(input: { identifier: string }): Promise<MethodInitiateResult>;
  /** User-bound (OTP) phase 2. Throws {@link OtpNotAllowedError} when no OTP
   *  handler is configured, {@link SsoRequiredError} when the signed-in user has
   *  an address at an SSO-required verified domain, and
   *  {@link DeliveryUnavailableError} when the provider can't check codes
   *  (by default, for every identifier of the kind for the outage window). */
  completeOtp(input: { identifier: string; credential: string }): Promise<ResolvedUser>;
}
