import type { Queryable } from '../types.js';

/** The lowercase domain of an email address, or null when it has no `@`. */
export function emailDomainOf(email: string): string | null {
  const at = email.lastIndexOf('@');
  if (at < 0 || at === email.length - 1) return null;
  return email.slice(at + 1).toLowerCase();
}

const SELECT_TENANT_VERIFIED_DOMAIN = `
  SELECT 1
  FROM tenant_email_domains
  WHERE tenant_id = $1
    AND domain = $2
    AND verified_at IS NOT NULL
    AND deleted_at IS NULL
  LIMIT 1
`;

/** Whether `tenantId` has verified `domain` (a live, verified tenant_email_domains row). */
export async function tenantHasVerifiedDomain(db: Queryable, tenantId: number, domain: string): Promise<boolean> {
  const { rows } = await db.query(SELECT_TENANT_VERIFIED_DOMAIN, [tenantId, domain]);
  return rows.length > 0;
}

const SELECT_SSO_REQUIRED_DOMAIN = `
  SELECT d.domain
  FROM tenant_email_domains d
  WHERE d.domain = ANY ($1::text[])
    AND d.sso_required
    AND d.verified_at IS NOT NULL
    AND d.deleted_at IS NULL
  LIMIT 1
`;

// The domains of every live email address the user holds.
const SELECT_USER_EMAIL_DOMAINS = `
  SELECT DISTINCT lower(substring(ucm.code FROM '@([^@]*)$')) AS domain
  FROM user_communication_methods ucm
  JOIN communication_channels cc
    ON cc.communication_channel_id = ucm.communication_channel_id
  WHERE ucm.user_id = $1
    AND cc.name = 'email'
    AND ucm.deleted_at IS NULL
    AND cc.deleted_at IS NULL
`;

/** The first of `domains` that is verified by some tenant with SSO required, or null. */
export async function ssoRequiredDomain(db: Queryable, domains: readonly string[]): Promise<string | null> {
  if (domains.length === 0) return null;
  const { rows } = await db.query<{ domain: string }>(SELECT_SSO_REQUIRED_DOMAIN, [domains]);
  return rows[0]?.domain ?? null;
}

/** The SSO-required domain among the user's email addresses, or null. */
export async function ssoRequiredDomainForUser(db: Queryable, userId: number): Promise<string | null> {
  const { rows } = await db.query<{ domain: string | null }>(SELECT_USER_EMAIL_DOMAINS, [userId]);
  return ssoRequiredDomain(
    db,
    rows.map((r) => r.domain).filter((d): d is string => !!d),
  );
}
