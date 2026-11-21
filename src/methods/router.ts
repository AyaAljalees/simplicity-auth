import { AuthError, InvalidInputError } from '../errors.js';
import {
  emailDomainOf,
  ssoRequiredDomain,
  ssoRequiredDomainForUser,
  tenantRequiresSso,
} from '../internal/email-domain.js';
import type { Logger, Queryable } from '../types.js';
import { DeliveryUnavailableError, OtpNotAllowedError, SsoRequiredError, UnknownIdentifierError } from './errors.js';
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

/**
 * How long, after a handler reports an outage, the router answers every
 * identifier of that kind with {@link DeliveryUnavailableError}.
 *
 * The request that opens the window necessarily belongs to an account holder
 * (only they reach the provider), so during an outage an attacker can learn
 * about roughly one identifier per window, per server process. Shorter means
 * more of that; longer means honest people wait longer after the provider recovers.
 */
export const OTP_OUTAGE_WINDOW_SECONDS = 60;

/** Without an app logger, failures still go somewhere visible: a provider outage must never be silent. */
const consoleLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: (data, msg) => console.warn(msg, data),
  error: (data, msg) => console.error(msg, data),
};

/** A short, identifier-free token from an error's `name` or `code`, or undefined. */
function safeToken(value: unknown): string | undefined {
  const text = typeof value === 'number' && Number.isFinite(value) ? String(value) : value;
  return typeof text === 'string' && SAFE_CODE.test(text) ? text : undefined;
}

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
  const logger = options.logger ?? consoleLogger;
  const otpAllowed = !!otpHandler && ('initiate' in otpHandler || !!(otpHandler.email || otpHandler.phone));
  /** Per kind and phase, when the current outage window closes (epoch ms). */
  const outageUntil = new Map<string, number>();

  /**
   * Logs a failure without the identifier: a provider's message can quote it,
   * so only the kind and a token-shaped name and code (the error's own, or its
   * `cause`'s) are kept. Never throws: an error here would turn the answer back
   * into an error for known identifiers only.
   */
  function report(level: 'warn' | 'error', msg: string, identifier: string, err: unknown): void {
    try {
      const e = err as { name?: unknown; code?: unknown; cause?: { code?: unknown } } | null;
      const data: Record<string, unknown> = {
        kind: identifierKind(identifier),
        error: (err instanceof Error && safeToken(e?.name)) || 'Error',
      };
      const code = safeToken(e?.code) ?? safeToken(e?.cause?.code);
      if (code) data.code = code;
      logger[level](data, msg);
    } catch {
      // Swallowed on purpose; see above.
    }
  }

  /** Throws {@link DeliveryUnavailableError} while an outage window is open for this identifier's kind and phase. */
  function refuseDuringOutage(phase: 'initiate' | 'complete', identifier: string): void {
    const until = outageUntil.get(`${phase}:${identifierKind(identifier)}`) ?? 0;
    const remaining = until - Date.now();
    if (remaining > 0) {
      throw new DeliveryUnavailableError(undefined, { retryAfterSeconds: Math.ceil(remaining / 1000) });
    }
  }

  /** Opens an outage window and returns the error to answer this request with. */
  function openOutage(
    phase: 'initiate' | 'complete',
    identifier: string,
    err: DeliveryUnavailableError,
  ): DeliveryUnavailableError {
    outageUntil.set(`${phase}:${identifierKind(identifier)}`, Date.now() + OTP_OUTAGE_WINDOW_SECONDS * 1000);
    report('error', `OTP ${phase} unavailable`, identifier, err.cause ?? err);
    return new DeliveryUnavailableError(err.message, { cause: err, retryAfterSeconds: OTP_OUTAGE_WINDOW_SECONDS });
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
      // Before anything account-dependent, so everyone of this kind gets the same answer.
      if (!options.revealUnknownIdentifiers) refuseDuringOutage('initiate', identifier);
      const user = await handler.resolveUser?.({ db: options.db, identifier });
      if (user === null && options.revealUnknownIdentifiers) throw new UnknownIdentifierError();
      // From here on work runs only for a known identifier. In hide mode, a
      // failure must not mark it as having an account.
      try {
        // The same verdict completeOtp reaches on the resolved user. By default it
        // answers as for an unknown identifier, so it doesn't reveal whose a phone is.
        const ownerRequires = user ? await ssoRequiredDomainForUser(q, user.userId) : null;
        if (ownerRequires && options.revealSsoRequiredUsers) throw new SsoRequiredError(ownerRequires);
        if (ownerRequires) return { otpSent: true };
        return await handler.initiate({ db: options.db, identifier });
      } catch (err) {
        if (options.revealUnknownIdentifiers) {
          // Nothing to hide: say plainly that the code didn't go out.
          if (err instanceof AuthError) throw err;
          report('error', 'OTP initiate failed', identifier, err);
          throw new DeliveryUnavailableError(undefined, { cause: err });
        }
        if (err instanceof DeliveryUnavailableError) throw openOutage('initiate', identifier, err);
        if (err instanceof AuthError) throw err;
        report('error', 'OTP initiate failed', identifier, err);
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
      const handler = handlerFor(identifier);
      if (!options.revealUnknownIdentifiers) refuseDuringOutage('complete', identifier);
      let user: ResolvedUser;
      try {
        user = await handler.complete({ db: options.db, identifier, credential });
      } catch (err) {
        // A provider that can't check codes must not make a right code look wrong.
        if (err instanceof DeliveryUnavailableError && !options.revealUnknownIdentifiers) {
          throw openOutage('complete', identifier, err);
        }
        throw err;
      }
      // Checked on the resolved user, not just the identifier: someone whose
      // email is at an SSO-required domain can't sign in by phone either.
      const required = await ssoRequiredDomainForUser(q, user.userId);
      if (required) throw new SsoRequiredError(required);
      return user;
    },
  };
}
