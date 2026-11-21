import { AuthError } from '../errors.js';

/**
 * Thrown when OTP (user-bound) sign-in is attempted but the router has no OTP
 * handler configured — an SSO-only product.
 */
export class OtpNotAllowedError extends AuthError {
  override readonly name = 'OtpNotAllowedError';
  override readonly code = 'OTP_NOT_ALLOWED' as const;

  constructor(message: string = 'OTP sign-in is not allowed') {
    super(message);
  }
}

/**
 * Thrown by a handler's `complete` when the submitted credential fails
 * verification (wrong/expired OTP, invalid id_token, unverifiable claims),
 * or when a verified identity has no user and no provisioning is allowed.
 */
export class VerificationFailedError extends AuthError {
  override readonly name = 'VerificationFailedError';
  override readonly code = 'VERIFICATION_FAILED' as const;
  /**
   * Why, more specifically than the message, for the people who run the
   * identity provider (see `AuthHttpConfig.onSignInFailure`): the provider's own
   * error, say. The message stays generic because it can reach the person signing in.
   */
  readonly detail?: string;

  constructor(message: string = 'Verification failed', options: { detail?: string } = {}) {
    super(message);
    if (options.detail !== undefined) this.detail = options.detail;
  }
}

/**
 * Thrown by the OIDC handler when the IdP asserts an email address at a domain
 * the auth domain's tenant has not verified (`tenant_email_domains`). An IdP is
 * trusted only for the domains its tenant has proven it owns, so a tenant admin
 * can't use their own IdP to sign in as someone else's user.
 */
export class EmailDomainNotVerifiedError extends AuthError {
  override readonly name = 'EmailDomainNotVerifiedError';
  override readonly code = 'EMAIL_DOMAIN_NOT_VERIFIED' as const;
  readonly tenantId: number;
  readonly domain: string;

  constructor(tenantId: number, domain: string, message?: string) {
    super(message ?? `Tenant ${tenantId} has not verified the email domain ${domain}`);
    this.tenantId = tenantId;
    this.domain = domain;
  }
}

/**
 * Thrown by the router's OTP path when the email address, or an email address
 * of the user being signed in, is at a verified domain that requires SSO. That
 * user must sign in through their organization's IdP, on any sub-domain.
 */
export class SsoRequiredError extends AuthError {
  override readonly name = 'SsoRequiredError';
  override readonly code = 'SSO_REQUIRED' as const;
  readonly domain: string;

  constructor(domain: string, message?: string) {
    super(message ?? `Sign-in for ${domain} addresses requires SSO`);
    this.domain = domain;
  }
}

/**
 * Thrown by an app's sign-in hook to refuse a sign-in, e.g. a verified user
 * with no live role in an active workspace. The message is the app's and is
 * what the person sees. `code` defaults to `SIGN_IN_REFUSED`; on an OIDC
 * sign-in with `signInErrorPath`, only the code reaches the page, so pass your
 * own code when the page needs to tell refusals apart.
 */
export class SignInRefusedError extends AuthError {
  override readonly name = 'SignInRefusedError';
  override readonly code: string;

  constructor(message: string, code: string = 'SIGN_IN_REFUSED') {
    super(message);
    this.code = code;
  }
}

/**
 * Thrown when sign-in codes can't be sent or checked right now: the provider
 * is down, its credentials are wrong, or the like. It is honest to tell the
 * person to try again shortly, so the HTTP tier answers it with a 503.
 *
 * A handler throws it for a failure that would hit any recipient. The router
 * then answers every identifier of that kind with it, account or not, for
 * {@link OTP_OUTAGE_WINDOW_SECONDS}, so the answer doesn't reveal who has an
 * account. An app's `sendCode` can throw it to mark a provider error as an
 * outage. A failure about one recipient must not be this error.
 */
export class DeliveryUnavailableError extends AuthError {
  override readonly name = 'DeliveryUnavailableError';
  override readonly code = 'DELIVERY_UNAVAILABLE' as const;
  /** How long until it's worth trying again, when the router knows. */
  readonly retryAfterSeconds?: number;

  constructor(
    message: string = "Sign-in codes can't be sent or checked right now",
    options: { cause?: unknown; retryAfterSeconds?: number } = {},
  ) {
    super(message, { cause: options.cause });
    if (options.retryAfterSeconds !== undefined) this.retryAfterSeconds = options.retryAfterSeconds;
  }
}

/**
 * Thrown by the router's OTP path, only with `revealUnknownIdentifiers`, for an
 * email address or phone number that no account uses, so the page can say so.
 */
export class UnknownIdentifierError extends AuthError {
  override readonly name = 'UnknownIdentifierError';
  override readonly code = 'UNKNOWN_IDENTIFIER' as const;

  constructor(message: string = 'No account uses that email address or phone number') {
    super(message);
  }
}
