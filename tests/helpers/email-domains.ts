import type { TestDb } from './test-db.js';

/**
 * Give `tenantId` a verified email domain, as a global admin would through the
 * privileged pool (the superuser pool here; app-init as the audit actor).
 * Returns the tenant_email_domain_id.
 */
export async function seedVerifiedDomain(
  db: TestDb,
  tenantId: number,
  domain: string,
  opts: { ssoRequired?: boolean } = {},
): Promise<number> {
  const c = await db.pool.connect();
  try {
    await c.query('BEGIN');
    await c.query(`SELECT set_config('app.actor_id', $1, true)`, [String(db.ids.appInit)]);
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO tenant_email_domains (tenant_id, domain, sso_required, verified_at)
       VALUES ($1, $2, $3, now())
       RETURNING tenant_email_domain_id AS id`,
      [tenantId, domain, opts.ssoRequired ?? false],
    );
    await c.query('COMMIT');
    return Number(rows[0]!.id);
  } catch (e) {
    await c.query('ROLLBACK');
    throw e;
  } finally {
    c.release();
  }
}
