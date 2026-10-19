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

  constructor(message: string = 'Verification failed') {
    super(message);
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
