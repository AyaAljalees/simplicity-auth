import { AuthError, InvalidInputError } from '../errors.js';
import {
  emailDomainOf,
  ssoRequiredDomain,
  ssoRequiredDomainForUser,
  tenantRequiresSso,
} from '../internal/email-domain.js';
import { noopLogger } from '../internal/noop-logger.js';
import type { Queryable } from '../types.js';
import { OtpNotAllowedError, SsoRequiredError } from './errors.js';
import type {
  AuthDomain,
  IdentifierKind,
  MethodHandler,
  MethodRouter,
  MethodRouterOptions,
  ResolvedUser,
  SignInOptions,
} from './types.js';

/** An identifier containing `@` is an email; anything else is a phone. */
export function identifierKind(identifier: string): IdentifierKind {
  return identifier.includes('@') ? 'email' : 'phone';
}

/** An error name or code such as `MessageRejected` or a SQLSTATE (`57P01`): short, with no `@` and no run of digits long enough to be a phone number. */
const SAFE_CODE = /^(?!.*\d{7})[A-Za-z0-9_]{1,32}$/;

const SELECT_TENANT_BY_SLUG = `
  SELECT tenant_id AS "tenantId"
  FROM tenants
  WHERE slug = $1 AND deleted_at IS NULL
  LIMIT 1
`;

const SELECT_AUTH_DOMAINS_BY_TENANT = `
  SELECT
    auth_domain_id     AS "authDomainId",
    tenant_id          AS "tenantId",
    display_name       AS "displayName",
    integration_type   AS "integrationType",
    integration_params AS "integrationParams"
  FROM auth_domains
  WHERE tenant_id = $1 AND deleted_at IS NULL
  ORDER BY display_name
`;

interface TenantRow {
  tenantId: number;
}

/**
 * Build the tenant-centric sign-in router: **discovery** (`signInOptions`) and
 * the **user-bound OTP path** (`initiateOtp`/`completeOtp`). Code sign-in is
 * open to everyone except addresses at a verified email domain that requires
 * SSO (`tenant_email_domains.sso_required`) — refused here, on every
 * sub-domain, not just hidden in the UI.
 *
 * OIDC is intentionally not routed here: it has a richer `authorize`/`callback`
 * shape (PKCE + login-state) handled by `@smplcty/auth/oidc`. Resolve the
 * tenant's OIDC `auth_domains` via `signInOptions`, then drive that handler.
 *
 * ```ts
 * const router = createMethodRouter({ db: pool, otpHandler: twilioVerifyHandler({ client }) });
 * const opts = await router.signInOptions({ tenantSlug: 'acme' });
 * // opts = { tenantId, authDomains: [...OIDC IdPs...], otpAllowed }
 * //   render: a button per authDomain (→ @smplcty/auth/oidc) + an OTP form iff otpAllowed
 * ```
 */
export function createMethodRouter(options: MethodRouterOptions): MethodRouter {
  const { otpHandler } = options;
  const q = options.db as Queryable;
  const logger = options.logger ?? noopLogger;
  const otpAllowed = !!otpHandler && ('initiate' in otpHandler || !!(otpHandler.email || otpHandler.phone));

  /** Logs a failed `initiate` without the identifier: a provider's message can quote it, so only a token-shaped name and code are kept. */
  function reportInitiateFailure(identifier: string, err: unknown): void {
    const name = err instanceof Error ? err.name : typeof err;
    const code = (err as { code?: unknown } | null)?.code;
    const data: Record<string, unknown> = {
      kind: identifierKind(identifier),
      error: SAFE_CODE.test(name) ? name : 'Error',
    };
    if (typeof code === 'string' && SAFE_CODE.test(code)) data.code = code;
    try {
      logger.error(data, 'OTP initiate failed');
    } catch {
      // A throwing logger must not turn the answer back into an error for known identifiers only.
    }
  }

  /** The handler for this identifier: the single one, or the one for its kind. */
  function handlerFor(identifier: string): MethodHandler {
    if (!otpHandler) throw new OtpNotAllowedError('No OTP handler is configured');
    if ('initiate' in otpHandler) return otpHandler;
    const kind = identifierKind(identifier);
    const handler = otpHandler[kind];
    if (!handler) throw new OtpNotAllowedError(`Code sign-in by ${kind} is not offered`);
    return handler;
  }

  /** Refuses an address at a domain that requires SSO, before anything else, so it is told to use SSO. */
  async function refuseSsoRequiredDomain(identifier: string): Promise<void> {
    const domain = emailDomainOf(identifier);
    const required = domain ? await ssoRequiredDomain(q, [domain]) : null;
    if (required) throw new SsoRequiredError(required);
  }

  return {
    async signInOptions({ tenantSlug }): Promise<SignInOptions | null> {
      if (typeof tenantSlug !== 'string' || tenantSlug.length === 0) {
        throw new InvalidInputError('tenantSlug must be a non-empty string');
      }
      const { rows } = await q.query<TenantRow>(SELECT_TENANT_BY_SLUG, [tenantSlug]);
      const tenant = rows[0];
      if (!tenant) {
        return null;
      }
      const { rows: authDomains } = await q.query<AuthDomain>(SELECT_AUTH_DOMAINS_BY_TENANT, [tenant.tenantId]);
      // bigint ids arrive from pg as strings; the public shapes are `number`.
      return {
        tenantId: Number(tenant.tenantId),
        authDomains: authDomains.map((d) => ({
          ...d,
          authDomainId: Number(d.authDomainId),
          tenantId: Number(d.tenantId),
        })),
        otpAllowed,
        ssoRequired: await tenantRequiresSso(q, tenant.tenantId),
      };
    },

    async initiateOtp({ identifier }) {
      if (typeof identifier !== 'string' || identifier.length === 0) {
        throw new InvalidInputError('identifier must be a non-empty string');
      }
      await refuseSsoRequiredDomain(identifier);
      const handler = handlerFor(identifier);
      // The same verdict completeOtp reaches on the resolved user. By default it
      // answers as for an unknown identifier, so it doesn't reveal whose a phone is.
      const user = await handler.resolveUser?.({ db: options.db, identifier });
      // From here on work runs only for a known identifier, so a failure would otherwise mark it as having an account.
      try {
        const ownerRequires = user ? await ssoRequiredDomainForUser(q, user.userId) : null;
        if (ownerRequires && options.revealSsoRequiredUsers) throw new SsoRequiredError(ownerRequires);
        if (ownerRequires) return { otpSent: true };
        return await handler.initiate({ db: options.db, identifier });
      } catch (err) {
        if (err instanceof AuthError) throw err;
        reportInitiateFailure(identifier, err);
        return { otpSent: true };
      }
    },

    async completeOtp({ identifier, credential }): Promise<ResolvedUser> {
      if (typeof identifier !== 'string' || identifier.length === 0) {
        throw new InvalidInputError('identifier must be a non-empty string');
      }
      if (typeof credential !== 'string' || credential.length === 0) {
        throw new InvalidInputError('credential must be a non-empty string');
      }
      await refuseSsoRequiredDomain(identifier);
      const user = await handlerFor(identifier).complete({ db: options.db, identifier, credential });
      // Checked on the resolved user, not just the identifier: someone whose
      // email is at an SSO-required domain can't sign in by phone either.
      const required = await ssoRequiredDomainForUser(q, user.userId);
      if (required) throw new SsoRequiredError(required);
      return user;
    },
  };
}
