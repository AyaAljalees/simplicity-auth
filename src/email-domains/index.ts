import { InvalidInputError } from '../errors.js';
import type { Queryable } from '../types.js';

/** Resolve a name's TXT records: one array of character-string chunks per record. */
export type ResolveTxt = (name: string) => Promise<string[][]>;

export interface EmailDomainVerifierOptions {
  /**
   * The label(s) the TXT record lives under, prepended to the domain — e.g.
   * `'_my-shiny-product'` publishes at `_my-shiny-product.acme.com`. Your
   * product's name, not this library's: customers see and publish it. An
   * underscore-prefixed label is recommended (RFC 8552): a bare label is a
   * hostname that can collide with a real host, or with a CNAME on that name.
   */
  recordLabel: string;
  /**
   * The value's prefix — e.g. `'my-shiny-product-verification'` publishes
   * `my-shiny-product-verification=<token>`.
   */
  valuePrefix: string;
  /**
   * Override the DNS lookup. Defaults to `node:dns/promises` `resolveTxt`
   * (loaded on first use). Pass a DNS-over-HTTPS resolver where `node:dns` is
   * unavailable (edge runtimes), or a fake in tests.
   */
  resolveTxt?: ResolveTxt;
}

/** The TXT record a customer publishes to prove they own a domain. */
export interface EmailDomainVerificationRecord {
  readonly type: 'TXT';
  /** Fully qualified record name, e.g. `_my-shiny-product.acme.com`. */
  readonly name: string;
  readonly value: string;
}

export interface EmailDomainVerifier {
  /**
   * The record to show the customer for a `tenant_email_domains` row (its
   * `domain` and `verification_token`, which a settings admin can read).
   */
  record(row: { domain: string; verificationToken: string }): EmailDomainVerificationRecord;
  /**
   * Look the row's record up in DNS and, if it carries the row's token, mark
   * the domain verified. Returns whether the domain is verified. Safe to call
   * on any user's behalf: it only ever records what DNS proves. Retry when the
   * customer has just published the record — DNS can take minutes to show it.
   *
   * **Contract:** `db` connects as `app_privileged` (app_rls cannot write
   * `verified_at`) with an audit actor set — e.g. a client inside
   * `withServiceContext`, since `updated_by` is NOT NULL.
   *
   * @throws {InvalidInputError} If no live row has that id.
   */
  verify(db: Queryable, tenantEmailDomainId: number): Promise<boolean>;
}

const LABEL_PATTERN = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;
// DNS lookups that mean "no such record yet", not a failure.
const NO_RECORD_CODES = new Set(['ENOTFOUND', 'ENODATA']);

const SELECT_ROW = `
  SELECT domain, verification_token AS "verificationToken", verified_at AS "verifiedAt"
  FROM tenant_email_domains
  WHERE tenant_email_domain_id = $1 AND deleted_at IS NULL
`;

// The token guard keeps a row from being verified by a lookup of a token it
// no longer carries.
const MARK_VERIFIED = `
  UPDATE tenant_email_domains
  SET verified_at = now()
  WHERE tenant_email_domain_id = $1
    AND verification_token = $2
    AND verified_at IS NULL
    AND deleted_at IS NULL
`;

interface Row {
  domain: string;
  verificationToken: string;
  verifiedAt: Date | null;
}

const nodeResolveTxt: ResolveTxt = async (name) => {
  const dns = await import('node:dns/promises');
  return dns.resolveTxt(name);
};

/**
 * Build the DNS verifier for `tenant_email_domains` (opt-in subpath
 * `@smplcty/auth/email-domains`). An auth domain authenticates only email
 * addresses at its tenant's verified domains; this is how a domain becomes
 * verified. A global admin can instead mark a row verified directly
 * (`UPDATE tenant_email_domains SET verified_at = now() …` through the
 * privileged pool) for a customer who can't edit DNS.
 *
 * @example
 * ```ts
 * const verifier = emailDomainVerifier({
 *   recordLabel: '_my-shiny-product',
 *   valuePrefix: 'my-shiny-product-verification',
 * });
 * verifier.record(row); // { type: 'TXT', name: '_my-shiny-product.acme.com', value: 'my-shiny-product-verification=…' }
 * const verified = await withServiceContext(privilegedPool, 'domain-verifier', (c) => verifier.verify(c, row.id));
 * ```
 *
 * @throws {InvalidInputError} If `recordLabel` or `valuePrefix` is malformed.
 */
export function emailDomainVerifier(options: EmailDomainVerifierOptions): EmailDomainVerifier {
  const { recordLabel, valuePrefix } = options;
  if (typeof recordLabel !== 'string' || !LABEL_PATTERN.test(recordLabel)) {
    throw new InvalidInputError('recordLabel must be one or more DNS labels (letters, digits, "_" and "-")');
  }
  if (typeof valuePrefix !== 'string' || valuePrefix.length === 0 || /[\s=]/.test(valuePrefix)) {
    throw new InvalidInputError('valuePrefix must be a non-empty string without whitespace or "="');
  }
  const resolveTxt = options.resolveTxt ?? nodeResolveTxt;

  function record(row: { domain: string; verificationToken: string }): EmailDomainVerificationRecord {
    return { type: 'TXT', name: `${recordLabel}.${row.domain}`, value: `${valuePrefix}=${row.verificationToken}` };
  }

  return {
    record,

    async verify(db, tenantEmailDomainId) {
      if (!Number.isInteger(tenantEmailDomainId) || tenantEmailDomainId <= 0) {
        throw new InvalidInputError('tenantEmailDomainId must be a positive integer');
      }
      const { rows } = await db.query<Row>(SELECT_ROW, [tenantEmailDomainId]);
      const row = rows[0];
      if (!row) throw new InvalidInputError(`No email domain with id ${tenantEmailDomainId}`);
      if (row.verifiedAt) return true;

      const expected = record(row);
      let records: string[][];
      try {
        records = await resolveTxt(expected.name);
      } catch (err) {
        if (NO_RECORD_CODES.has((err as { code?: string }).code ?? '')) return false;
        throw err;
      }
      // A long TXT value arrives split into 255-byte chunks; rejoin each record.
      if (!records.some((chunks) => chunks.join('') === expected.value)) return false;

      const marked = await db.query(MARK_VERIFIED, [tenantEmailDomainId, row.verificationToken]);
      // Zero rows: removed (or re-verified) since the read above.
      return (marked.rowCount ?? 0) > 0;
    },
  };
}
