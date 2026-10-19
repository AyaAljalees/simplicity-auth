import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { isDevOtpEnrolled } from '../src/index.js';
import { startTestDb, type TestDb } from './helpers/test-db.js';

// The grant matrix is a security boundary, so it is asserted exactly — both the
// positives (each role has what it needs) and, more importantly, the negatives
// (app_rls, the per-request RLS role, has NO write on reference data, NO access
// at all to the credential tables, and cannot raw-INSERT a user). A grant the
// admin pool needs is missed only in staging/prod because the test admin pool
// is a superuser; these tests connect AS the actual roles so that can't happen.
//
// app_rls       — the RLS-bound request role.
// app_privileged — the trusted, BYPASSRLS auth machinery; member of app_rls.
const EXPECTED: Record<string, { rls: string[]; privileged: string[] }> = {
  // Reference data — read-only for the request role; seeded by the owner.
  roles: { rls: ['SELECT'], privileged: ['SELECT'] },
  communication_channels: { rls: ['SELECT'], privileged: ['SELECT'] },
  // RLS-gated identity tables — request role writes, gated by policy.
  tenants: { rls: ['SELECT', 'INSERT', 'UPDATE'], privileged: ['SELECT', 'INSERT', 'UPDATE'] },
  user_roles: { rls: ['SELECT', 'INSERT', 'UPDATE'], privileged: ['SELECT', 'INSERT', 'UPDATE'] },
  user_communication_methods: { rls: ['SELECT', 'INSERT', 'UPDATE'], privileged: ['SELECT', 'INSERT', 'UPDATE'] },
  auth_domains: { rls: ['SELECT', 'INSERT', 'UPDATE'], privileged: ['SELECT', 'INSERT', 'UPDATE'] },
  // Column-scoped writes only (see email-domains.test.ts), so no table-level
  // INSERT/UPDATE: the verified state is out of app_rls's reach.
  tenant_email_domains: { rls: ['SELECT'], privileged: ['SELECT'] },
  // users — request role reads + RLS-gated UPDATE; INSERT is privileged-only
  // (OIDC provisioning) since app_rls provisions via auth_create_user (DEFINER).
  users: { rls: ['SELECT', 'UPDATE'], privileged: ['SELECT', 'INSERT', 'UPDATE'] },
  // Credentials — app_rls gets NOTHING; only the privileged machinery.
  sessions: { rls: [], privileged: ['SELECT', 'INSERT', 'UPDATE'] },
  dev_otp_enrollments: { rls: [], privileged: ['SELECT', 'INSERT', 'UPDATE'] },
};
const PRIVS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];

let db: TestDb;
let appRls: pg.Pool;
let appPrivileged: pg.Pool;

// Whether `role` holds `priv` on public.`table`, asked via has_table_privilege
// (answers regardless of the connected role — so the superuser pool can read
// app_rls's / app_privileged's grants directly). app_privileged is a member of
// app_rls, so its effective privileges include everything app_rls holds.
async function holds(role: string, table: string, priv: string): Promise<boolean> {
  const { rows } = await db.pool.query<{ ok: boolean }>(`SELECT has_table_privilege($1, 'public.' || $2, $3) AS ok`, [
    role,
    table,
    priv,
  ]);
  return rows[0]!.ok;
}

beforeAll(async () => {
  db = await startTestDb();
  appRls = new pg.Pool({ connectionString: db.appRlsConnectionString, max: 2 });
  appPrivileged = new pg.Pool({ connectionString: db.appPrivilegedConnectionString, max: 2 });
});

afterAll(async () => {
  await appRls.end();
  await appPrivileged.end();
  await db.shutdown();
});

describe('grant matrix', () => {
  it.each(Object.keys(EXPECTED))('app_rls has exactly the intended privileges on %s', async (table) => {
    for (const priv of PRIVS) {
      const expected = EXPECTED[table]!.rls.includes(priv);
      expect(await holds('app_rls', table, priv), `app_rls ${priv} on ${table} should be ${expected}`).toBe(expected);
    }
  });

  it.each(Object.keys(EXPECTED))('app_privileged has exactly the intended privileges on %s', async (table) => {
    for (const priv of PRIVS) {
      const expected = EXPECTED[table]!.privileged.includes(priv);
      expect(
        await holds('app_privileged', table, priv),
        `app_privileged ${priv} on ${table} should be ${expected}`,
      ).toBe(expected);
    }
  });

  it('grants USAGE on the serial PK sequences so INSERTs do not trip a sequence error', async () => {
    // schema-flow auto-derives `GRANT USAGE, SELECT ON SEQUENCE` from a table's
    // INSERT grant; tenants.tenant_id (app_rls INSERT) and users.user_id
    // (app_privileged INSERT) are the two representative serial keys.
    const { rows } = await db.pool.query<{ rls: boolean; priv: boolean }>(
      `SELECT has_sequence_privilege('app_rls', 'public.tenants_tenant_id_seq', 'USAGE') AS rls,
              has_sequence_privilege('app_privileged', 'public.users_user_id_seq', 'USAGE') AS priv`,
    );
    expect(rows[0]?.rls).toBe(true);
    expect(rows[0]?.priv).toBe(true);
  });
});

describe('credential tables are unreachable from app_rls', () => {
  it('app_rls cannot read or write sessions', async () => {
    await expect(appRls.query('SELECT 1 FROM sessions')).rejects.toThrow(/permission denied/i);
    await expect(appRls.query(`INSERT INTO sessions (session_id) VALUES ('x')`)).rejects.toThrow(/permission denied/i);
  });

  it('app_rls cannot read or write dev_otp_enrollments — and the read that ran through the admin pool works AS app_privileged', async () => {
    await expect(appRls.query('SELECT 1 FROM dev_otp_enrollments')).rejects.toThrow(/permission denied/i);
    // The pre-send enrollment check (the #12 outage) runs on the admin pool —
    // i.e. as app_privileged. It must succeed there and be denied to app_rls.
    await expect(isDevOtpEnrolled(appPrivileged, db.ids.ucm.alice)).resolves.toBe(false);
    await expect(isDevOtpEnrolled(appRls, db.ids.ucm.alice)).rejects.toThrow(/permission denied/i);
  });

  it('app_rls cannot raw-INSERT a user or write reference data', async () => {
    await expect(appRls.query(`INSERT INTO users (name, kind) VALUES ('x', 'human')`)).rejects.toThrow(
      /permission denied|row-level security/i,
    );
    await expect(appRls.query(`INSERT INTO roles (name) VALUES ('x')`)).rejects.toThrow(/permission denied/i);
    await expect(appRls.query(`INSERT INTO communication_channels (name) VALUES ('x')`)).rejects.toThrow(
      /permission denied/i,
    );
  });
});
