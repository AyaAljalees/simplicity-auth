import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { startTestDb, type TestDb } from './helpers/test-db.js';

// SECURITY DEFINER functions run as their owner and read the auth tables
// unfiltered. When pg_temp is absent from their search_path, Postgres searches
// the caller's temp schema FIRST for relation names, so a caller who can run
// SQL could shadow user_roles with a temp table and have the function answer
// from it. Listing pg_temp last keeps public ahead of it. (#16)
describe('SECURITY DEFINER search_path', () => {
  let db: TestDb;

  beforeAll(async () => {
    db = await startTestDb();
  });
  afterAll(async () => {
    await db.shutdown();
  });

  it('lists pg_temp last on every SECURITY DEFINER function', async () => {
    const { rows } = await db.pool.query<{ name: string; config: string[] | null }>(
      `SELECT p.proname AS name, p.proconfig AS config
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE p.prosecdef AND n.nspname = 'public'
       ORDER BY 1`,
    );
    expect(rows.length).toBeGreaterThan(0);
    for (const { name, config } of rows) {
      const searchPath = config?.find((c) => c.startsWith('search_path='));
      const schemas = searchPath
        ?.slice('search_path='.length)
        .split(',')
        .map((s) => s.trim().replace(/^"|"$/g, ''));
      expect({ name, last: schemas?.at(-1) }).toEqual({ name, last: 'pg_temp' });
    }
  });

  it('ignores a caller temp table that shadows user_roles', async () => {
    // A dedicated connection as the RLS-bound app role (it holds TEMP through
    // PUBLIC by default), so no cached plan from another test can mask the result.
    const client = new pg.Client({ connectionString: db.appRlsConnectionString });
    await client.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('app.actor_id', $1, true)`, [String(db.ids.users.alice)]);
      // Alice holds 'user' on acme only; the forged row claims 'security' everywhere.
      await client.query(
        `CREATE TEMP TABLE user_roles (user_id bigint, role_id bigint, tenant_id bigint, deleted_at timestamptz)
         ON COMMIT DROP`,
      );
      await client.query(`INSERT INTO user_roles VALUES ($1, $2, NULL, NULL)`, [
        db.ids.users.alice,
        db.ids.roles.security,
      ]);
      const { rows } = await client.query<{ ok: boolean }>(`SELECT auth_has_role('security', NULL) AS ok`);
      expect(rows[0]!.ok).toBe(false);
    } finally {
      await client.query('ROLLBACK').catch(() => {});
      await client.end();
    }
  });
});
