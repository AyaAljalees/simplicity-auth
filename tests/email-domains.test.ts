import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import {
  createMethodRouter,
  InvalidInputError,
  SsoRequiredError,
  withServiceContext,
  type MethodHandler,
} from '../src/index.js';
import { emailDomainVerifier, type ResolveTxt } from '../src/email-domains/index.js';
import { twilioVerifyHandler } from '../src/methods/twilio/index.js';
import { seedVerifiedDomain } from './helpers/email-domains.js';
import { startTestDb, type TestDb } from './helpers/test-db.js';

// tenant_email_domains is the boundary that stops a tenant admin's IdP from
// vouching for someone else's users (#21). These tests pin who can write the
// verified state, how DNS proves ownership, and that an SSO-required domain
// closes code sign-in everywhere.

let db: TestDb;
let appRls: pg.Pool;
let appPrivileged: pg.Pool;
let acmeSettings: number; // settings admin of acme only

async function asAppInit<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await db.pool.connect();
  try {
    await c.query('BEGIN');
    await c.query(`SELECT set_config('app.actor_id', $1, true)`, [String(db.ids.appInit)]);
    const result = await fn(c);
    await c.query('COMMIT');
    return result;
  } catch (e) {
    await c.query('ROLLBACK');
    throw e;
  } finally {
    c.release();
  }
}

// Run fn as app_rls impersonating `actorId`, always rolled back.
async function asUser<T>(actorId: number, fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await appRls.connect();
  try {
    await c.query('BEGIN');
    await c.query(`SELECT set_config('app.actor_id', $1, true)`, [String(actorId)]);
    return await fn(c);
  } finally {
    await c.query('ROLLBACK').catch(() => {});
    c.release();
  }
}

// Each probe runs in its own savepoint so a refused write doesn't end the transaction.
async function attempt(c: pg.PoolClient, sql: string, params: unknown[]): Promise<string | null> {
  await c.query('SAVEPOINT probe');
  try {
    await c.query(sql, params);
    await c.query('RELEASE SAVEPOINT probe');
    return null;
  } catch (e) {
    await c.query('ROLLBACK TO SAVEPOINT probe');
    return (e as { code?: string }).code ?? 'error';
  }
}

const INSUFFICIENT_PRIVILEGE = '42501';

async function claimDomain(tenantId: number, domain: string): Promise<{ id: number; token: string }> {
  return asAppInit(async (c) => {
    const { rows } = await c.query<{ id: string; token: string }>(
      `INSERT INTO tenant_email_domains (tenant_id, domain) VALUES ($1, $2)
       RETURNING tenant_email_domain_id AS id, verification_token AS token`,
      [tenantId, domain],
    );
    return { id: Number(rows[0]!.id), token: rows[0]!.token };
  });
}

async function verifiedAt(id: number): Promise<Date | null> {
  const { rows } = await db.pool.query<{ v: Date | null }>(
    `SELECT verified_at AS v FROM tenant_email_domains WHERE tenant_email_domain_id = $1`,
    [id],
  );
  return rows[0]!.v;
}

beforeAll(async () => {
  db = await startTestDb();
  appRls = new pg.Pool({ connectionString: db.appRlsConnectionString, max: 2 });
  appPrivileged = new pg.Pool({ connectionString: db.appPrivilegedConnectionString, max: 2 });
  acmeSettings = await asAppInit(async (c) => {
    const u = await c.query<{ id: string }>(
      `INSERT INTO users (name, kind) VALUES ('AcmeSettings', 'human') RETURNING user_id AS id`,
    );
    const id = Number(u.rows[0]!.id);
    await c.query(`INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES ($1, $2, $3)`, [
      id,
      db.ids.roles.settings,
      db.ids.tenants.acme,
    ]);
    return id;
  });
});

afterAll(async () => {
  await appRls.end();
  await appPrivileged.end();
  await db.shutdown();
});

describe('a tenant admin cannot mark a domain verified', () => {
  it('may claim a domain, toggle sso_required and remove it — but never write the token or verified_at', async () => {
    await asUser(acmeSettings, async (c) => {
      const claimed = await c.query<{ id: string; token: string }>(
        `INSERT INTO tenant_email_domains (tenant_id, domain) VALUES ($1, 'claimed.test')
         RETURNING tenant_email_domain_id AS id, verification_token AS token`,
        [db.ids.tenants.acme],
      );
      const id = Number(claimed.rows[0]!.id);
      // The token is server-generated.
      expect(claimed.rows[0]!.token).toMatch(/^[0-9a-f]{32}$/);

      expect(
        await attempt(c, `UPDATE tenant_email_domains SET sso_required = true WHERE tenant_email_domain_id = $1`, [id]),
      ).toBeNull();

      expect(
        await attempt(c, `UPDATE tenant_email_domains SET verified_at = now() WHERE tenant_email_domain_id = $1`, [id]),
      ).toBe(INSUFFICIENT_PRIVILEGE);
      expect(
        await attempt(c, `UPDATE tenant_email_domains SET verification_token = 'x' WHERE tenant_email_domain_id = $1`, [
          id,
        ]),
      ).toBe(INSUFFICIENT_PRIVILEGE);
      expect(
        await attempt(c, `UPDATE tenant_email_domains SET domain = 'mabulu.com' WHERE tenant_email_domain_id = $1`, [
          id,
        ]),
      ).toBe(INSUFFICIENT_PRIVILEGE);
      expect(
        await attempt(
          c,
          `INSERT INTO tenant_email_domains (tenant_id, domain, verified_at) VALUES ($1, 'sneaky.test', now())`,
          [db.ids.tenants.acme],
        ),
      ).toBe(INSUFFICIENT_PRIVILEGE);
      expect(
        await attempt(
          c,
          `INSERT INTO tenant_email_domains (tenant_id, domain, verification_token) VALUES ($1, 'copied.test', 'abc')`,
          [db.ids.tenants.acme],
        ),
      ).toBe(INSUFFICIENT_PRIVILEGE);

      expect(
        await attempt(c, `UPDATE tenant_email_domains SET deleted_at = now() WHERE tenant_email_domain_id = $1`, [id]),
      ).toBeNull();
    });
  });

  it("can't claim a domain for a tenant it doesn't administer", async () => {
    await asUser(acmeSettings, async (c) => {
      const code = await attempt(c, `INSERT INTO tenant_email_domains (tenant_id, domain) VALUES ($1, 'globex.com')`, [
        db.ids.tenants.globex,
      ]);
      expect(code).toBe(INSUFFICIENT_PRIVILEGE); // RLS WITH CHECK violation
    });
  });

  it('rejects a malformed or non-lowercase domain', async () => {
    for (const bad of ['Acme.com', 'acme', '-acme.com', 'acme..com', 'user@acme.com']) {
      await expect(claimDomain(db.ids.tenants.acme, bad), bad).rejects.toThrow(/tenant_email_domains_domain_check/);
    }
  });
});

describe('emailDomainVerifier', () => {
  const options = { recordLabel: '_my-shiny-product', valuePrefix: 'my-shiny-product-verification' };

  // A fake DNS zone: name → TXT records (each an array of chunks).
  function zone(records: Record<string, string[][]>): ResolveTxt {
    return async (name) => {
      const found = records[name];
      if (!found) throw Object.assign(new Error(`queryTxt ENOTFOUND ${name}`), { code: 'ENOTFOUND' });
      return found;
    };
  }

  const verifyAsService = (resolveTxt: ResolveTxt, id: number) =>
    withServiceContext(appPrivileged, 'transform-worker', (c) =>
      emailDomainVerifier({ ...options, resolveTxt }).verify(c, id),
    );

  it('describes the white-labeled record to publish', () => {
    const record = emailDomainVerifier(options).record({ domain: 'acme.com', verificationToken: 'abc123' });
    expect(record).toEqual({
      type: 'TXT',
      name: '_my-shiny-product.acme.com',
      value: 'my-shiny-product-verification=abc123',
    });
  });

  it('verifies only when the record carries this row’s token', async () => {
    const row = await claimDomain(db.ids.tenants.globex, 'verify-me.test');
    const name = '_my-shiny-product.verify-me.test';

    expect(await verifyAsService(zone({}), row.id)).toBe(false);
    expect(await verifyAsService(zone({ [name]: [['my-shiny-product-verification=wrong']] }), row.id)).toBe(false);
    expect(await verifiedAt(row.id)).toBeNull();

    // A long value arrives in chunks; other TXT records may sit beside it.
    const value = `my-shiny-product-verification=${row.token}`;
    const published = zone({ [name]: [['v=spf1 -all'], [value.slice(0, 20), value.slice(20)]] });
    expect(await verifyAsService(published, row.id)).toBe(true);
    expect(await verifiedAt(row.id)).toBeInstanceOf(Date);
    // Idempotent.
    expect(await verifyAsService(published, row.id)).toBe(true);
  });

  it("does not verify a domain with another tenant's token copied from public DNS", async () => {
    // Globex publishes its token; acme claims the same domain and points at it.
    const globex = await claimDomain(db.ids.tenants.globex, 'shared.test');
    const acme = await claimDomain(db.ids.tenants.acme, 'shared.test');
    const dns = zone({ '_my-shiny-product.shared.test': [[`my-shiny-product-verification=${globex.token}`]] });

    expect(await verifyAsService(dns, acme.id)).toBe(false);
    expect(await verifyAsService(dns, globex.id)).toBe(true);
    expect(await verifiedAt(acme.id)).toBeNull();
  });

  it('propagates a DNS failure that is not "no such record"', async () => {
    const row = await claimDomain(db.ids.tenants.globex, 'servfail.test');
    const failing: ResolveTxt = async () => {
      throw Object.assign(new Error('queryTxt ESERVFAIL'), { code: 'ESERVFAIL' });
    };
    await expect(verifyAsService(failing, row.id)).rejects.toThrow(/ESERVFAIL/);
  });

  it('cannot verify as app_rls, which has no write on verified_at', async () => {
    const row = await claimDomain(db.ids.tenants.globex, 'rls-verify.test');
    const dns = zone({ '_my-shiny-product.rls-verify.test': [[`my-shiny-product-verification=${row.token}`]] });
    await expect(
      asUser(db.ids.users.globalAdmin, (c) => emailDomainVerifier({ ...options, resolveTxt: dns }).verify(c, row.id)),
    ).rejects.toThrow(/permission denied/);
  });

  it('rejects malformed options and unknown rows', async () => {
    expect(() => emailDomainVerifier({ ...options, recordLabel: '' })).toThrow(InvalidInputError);
    expect(() => emailDomainVerifier({ ...options, recordLabel: '_a..b' })).toThrow(InvalidInputError);
    expect(() => emailDomainVerifier({ ...options, valuePrefix: 'has space' })).toThrow(InvalidInputError);
    expect(() => emailDomainVerifier({ ...options, valuePrefix: 'a=b' })).toThrow(InvalidInputError);
    await expect(verifyAsService(zone({}), 2 ** 31 - 1)).rejects.toBeInstanceOf(InvalidInputError);
  });
});

describe('a verified domain that requires SSO closes code sign-in everywhere', () => {
  // Accepts any code and signs in whoever owns the identifier; Alice by phone.
  const otp: MethodHandler = {
    async initiate() {
      return { otpSent: true };
    },
    async complete({ identifier }) {
      if (identifier === '+15555550100')
        return { userId: db.ids.users.alice, userCommunicationMethodId: db.ids.ucm.alice };
      const { rows } = await db.pool.query<{ u: string; m: string }>(
        `SELECT user_id AS u, user_communication_method_id AS m FROM user_communication_methods WHERE code = $1`,
        [identifier],
      );
      return { userId: Number(rows[0]!.u), userCommunicationMethodId: Number(rows[0]!.m) };
    },
  };
  const router = () => createMethodRouter({ db: db.pool, otpHandler: otp });
  const signIn = (identifier: string) => router().completeOtp({ identifier, credential: '000000' });

  it('before: an acme.com user can sign in by code', async () => {
    await expect(signIn('alice@acme.com')).resolves.toMatchObject({
      userId: db.ids.users.alice,
    });
  });

  it('a claimed but unverified domain requiring SSO changes nothing', async () => {
    const row = await claimDomain(db.ids.tenants.acme, 'acme.com');
    await asAppInit((c) =>
      c.query(`UPDATE tenant_email_domains SET sso_required = true WHERE tenant_email_domain_id = $1`, [row.id]),
    );
    await expect(signIn('alice@acme.com')).resolves.toMatchObject({
      userId: db.ids.users.alice,
    });
    await asAppInit((c) =>
      c.query(`UPDATE tenant_email_domains SET deleted_at = now() WHERE tenant_email_domain_id = $1`, [row.id]),
    );
  });

  describe('once acme verifies acme.com with SSO required', () => {
    beforeAll(async () => {
      await seedVerifiedDomain(db, db.ids.tenants.acme, 'acme.com', { ssoRequired: true });
    });

    it('refuses to send a code to an acme.com address', async () => {
      const err = await router()
        .initiateOtp({ identifier: 'Alice@ACME.com' })
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(SsoRequiredError);
      expect(err).toMatchObject({ code: 'SSO_REQUIRED', domain: 'acme.com' });
    });

    it('refuses code sign-in for an acme.com user, even by phone', async () => {
      await expect(signIn('alice@acme.com')).rejects.toBeInstanceOf(SsoRequiredError);
      await expect(signIn('+15555550100')).rejects.toBeInstanceOf(SsoRequiredError);
    });

    describe('through the Twilio handler', () => {
      const sent: string[] = [];
      const twilio = () =>
        createMethodRouter({
          db: db.pool,
          otpHandler: twilioVerifyHandler({
            client: {
              async sendVerificationCode({ to }) {
                sent.push(to);
                return true;
              },
              async verifyVerificationCode() {
                return true;
              },
            },
          }),
        });
      const addMethod = (user: number, channel: 'email' | 'phone', code: string) =>
        asAppInit((c) =>
          c.query(
            `INSERT INTO user_communication_methods (user_id, communication_channel_id, code)
             SELECT $1, communication_channel_id, $3 FROM communication_channels WHERE name = $2`,
            [user, channel, code],
          ),
        );

      beforeAll(async () => {
        await addMethod(db.ids.users.alice, 'phone', '+15555550111');
        await addMethod(db.ids.users.alice, 'email', 'alice@personal.example');
        await addMethod(db.ids.users.bob, 'phone', '+15555550122');
      });

      it.each([
        ['her phone', '+15555550111'],
        ['her email at a domain that does not require SSO', 'alice@personal.example'],
      ])('sends no code to an acme.com user by %s, and answers as for an unknown identifier', async (_label, id) => {
        sent.length = 0;
        const unknown = await twilio().initiateOtp({ identifier: '+15555550999' });

        const result = await twilio().initiateOtp({ identifier: id });

        expect(sent).toEqual([]);
        expect(result).toEqual(unknown);
      });

      it('still sends a code to an outsider by phone', async () => {
        sent.length = 0;

        await twilio().initiateOtp({ identifier: '+15555550122' });

        expect(sent).toEqual(['+15555550122']);
      });
    });

    it('leaves outsiders alone: bob@globex.com still signs in by code', async () => {
      await expect(signIn('bob@globex.com')).resolves.toMatchObject({
        userId: db.ids.users.bob,
      });
    });
  });
});
