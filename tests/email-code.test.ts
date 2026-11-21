import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import pg from 'pg';
import { generateSync } from 'otplib';
import { createMethodRouter, generateDevOtpSecret, VerificationFailedError } from '../src/index.js';
import { emailCodeHandler, type EmailCode } from '../src/methods/email-code/index.js';
import { startTestDb, type TestDb } from './helpers/test-db.js';

const SECRET = 'test-email-code-secret-at-least-32-bytes';

let db: TestDb;
let privileged: pg.Pool;
let sent: EmailCode[];

function router(pool: pg.Pool = privileged) {
  return createMethodRouter({
    db: pool,
    otpHandler: emailCodeHandler({
      codeSecret: SECRET,
      sendCode: async (message) => {
        sent.push(message);
      },
    }),
  });
}

async function requestCode(identifier: string): Promise<string> {
  const before = sent.length;
  await router().initiateOtp({ identifier });
  if (sent.length !== before + 1) throw new Error(`no code was sent to ${identifier}`);
  return sent.at(-1)!.code;
}

const signIn = (identifier: string, credential: string) => router().completeOtp({ identifier, credential });

const wrong = (code: string) => String((Number(code) + 1) % 1_000_000).padStart(6, '0');

beforeAll(async () => {
  db = await startTestDb();
  privileged = new pg.Pool({ connectionString: db.appPrivilegedConnectionString, max: 2 });
});

afterAll(async () => {
  await privileged.end();
  await db.shutdown();
});

beforeEach(async () => {
  sent = [];
  // Each test starts with no codes in flight and an empty resend window.
  await db.pool.query(
    `UPDATE email_sign_in_codes SET created_at = created_at - interval '1 day', superseded_at = now()`,
  );
});

describe('emailCodeHandler', () => {
  it('sends a six-digit code to a known address, and that code signs the user in', async () => {
    const code = await requestCode('alice@acme.com');
    expect(sent).toEqual([{ to: 'alice@acme.com', code }]);
    expect(code).toMatch(/^\d{6}$/);

    const user = await signIn('alice@acme.com', code);
    expect(user).toEqual({ userId: db.ids.users.alice, userCommunicationMethodId: db.ids.ucm.alice });
  });

  it('matches the address in any casing, as the user lookup does', async () => {
    const code = await requestCode('Alice@Acme.com');
    await expect(signIn('ALICE@acme.com', code)).resolves.toMatchObject({ userId: db.ids.users.alice });
  });

  it('accepts a code only once', async () => {
    const code = await requestCode('alice@acme.com');
    await signIn('alice@acme.com', code);
    await expect(signIn('alice@acme.com', code)).rejects.toBeInstanceOf(VerificationFailedError);
  });

  it('reports a send for an unknown address but sends nothing, and no code signs it in', async () => {
    await expect(router().initiateOtp({ identifier: 'nobody@acme.com' })).resolves.toEqual({ otpSent: true });
    expect(sent).toEqual([]);
    await expect(signIn('nobody@acme.com', '123456')).rejects.toBeInstanceOf(VerificationFailedError);
  });

  it("does not accept one user's code for another user", async () => {
    await requestCode('bob@globex.com');
    const aliceCode = await requestCode('alice@acme.com');
    await expect(signIn('bob@globex.com', aliceCode)).rejects.toBeInstanceOf(VerificationFailedError);
  });

  it('rejects a code after it expires', async () => {
    const code = await requestCode('alice@acme.com');
    await db.pool.query(
      `UPDATE email_sign_in_codes SET expires_at = now() - interval '1 second'
       WHERE user_communication_method_id = $1 AND superseded_at IS NULL`,
      [db.ids.ucm.alice],
    );
    await expect(signIn('alice@acme.com', code)).rejects.toBeInstanceOf(VerificationFailedError);
  });

  it('keeps a code valid for ten minutes', async () => {
    const before = Date.now();
    await requestCode('alice@acme.com');
    const { rows } = await db.pool.query<{ expires_at: Date }>(
      `SELECT expires_at FROM email_sign_in_codes
       WHERE user_communication_method_id = $1 AND superseded_at IS NULL`,
      [db.ids.ucm.alice],
    );
    const minutes = (rows[0]!.expires_at.getTime() - before) / 60_000;
    expect(minutes).toBeGreaterThan(9.9);
    expect(minutes).toBeLessThan(10.1);
  });

  it('kills a code after five wrong guesses, even if the sixth is right', async () => {
    const code = await requestCode('alice@acme.com');
    for (let i = 0; i < 5; i++) {
      await expect(signIn('alice@acme.com', wrong(code))).rejects.toBeInstanceOf(VerificationFailedError);
    }
    await expect(signIn('alice@acme.com', code)).rejects.toBeInstanceOf(VerificationFailedError);
  });

  it('still accepts the right code after four wrong guesses', async () => {
    const code = await requestCode('alice@acme.com');
    for (let i = 0; i < 4; i++) {
      await expect(signIn('alice@acme.com', wrong(code))).rejects.toBeInstanceOf(VerificationFailedError);
    }
    await expect(signIn('alice@acme.com', code)).resolves.toMatchObject({ userId: db.ids.users.alice });
  });

  it('replaces the previous code when a new one is sent, for good', async () => {
    const first = await requestCode('alice@acme.com');
    const second = await requestCode('alice@acme.com');
    await expect(signIn('alice@acme.com', second)).resolves.toMatchObject({ userId: db.ids.users.alice });
    await expect(signIn('alice@acme.com', first)).rejects.toBeInstanceOf(VerificationFailedError);
  });

  it('sends at most five codes per address in ten minutes, and the last one sent stays valid', async () => {
    for (let i = 0; i < 5; i++) await requestCode('alice@acme.com');
    const lastSent = sent.at(-1)!.code;

    await expect(router().initiateOtp({ identifier: 'alice@acme.com' })).resolves.toEqual({ otpSent: true });
    expect(sent).toHaveLength(5);
    await expect(signIn('alice@acme.com', lastSent)).resolves.toMatchObject({ userId: db.ids.users.alice });
  });

  it('sends again once the ten-minute window has passed', async () => {
    for (let i = 0; i < 5; i++) await requestCode('alice@acme.com');
    await db.pool.query(
      `UPDATE email_sign_in_codes SET created_at = created_at - interval '10 minutes 1 second'
       WHERE user_communication_method_id = $1`,
      [db.ids.ucm.alice],
    );
    await requestCode('alice@acme.com');
    expect(sent).toHaveLength(6);
  });

  describe('when sendCode fails (#36)', () => {
    /** A router whose sendCode throws while `failing` is true. Logging is silenced. */
    let failing = false;
    const flaky = () =>
      createMethodRouter({
        db: privileged,
        logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
        otpHandler: emailCodeHandler({
          codeSecret: SECRET,
          sendCode: async (message) => {
            if (failing) throw new Error('MessageRejected');
            sent.push(message);
          },
        }),
      });
    beforeEach(() => {
      failing = false;
    });

    it('keeps the code the person already has', async () => {
      await flaky().initiateOtp({ identifier: 'alice@acme.com' });
      const working = sent.at(-1)!.code;

      failing = true;
      await flaky().initiateOtp({ identifier: 'alice@acme.com' });

      await expect(signIn('alice@acme.com', working)).resolves.toMatchObject({ userId: db.ids.users.alice });
    });

    it('does not count a failed send toward the five-per-window limit', async () => {
      failing = true;
      for (let i = 0; i < 5; i++) await flaky().initiateOtp({ identifier: 'alice@acme.com' });
      failing = false;
      await flaky().initiateOtp({ identifier: 'alice@acme.com' });
      expect(sent).toHaveLength(1);
    });

    it('keeps a record of the code that never went out, which no one can use', async () => {
      failing = true;
      await flaky().initiateOtp({ identifier: 'alice@acme.com' });
      const { rows } = await db.pool.query(
        `SELECT delivery_failed_at IS NOT NULL AS failed, superseded_at IS NOT NULL AS dead
         FROM email_sign_in_codes WHERE user_communication_method_id = $1 AND created_at > now() - interval '1 minute'`,
        [db.ids.ucm.alice],
      );
      expect(rows).toEqual([{ failed: true, dead: true }]);
    });
  });

  it('stores neither the code nor a plain hash of it', async () => {
    const code = await requestCode('alice@acme.com');
    const { rows } = await db.pool.query<{ row: string }>(
      `SELECT row_to_json(c)::text AS row FROM email_sign_in_codes c
       WHERE user_communication_method_id = $1 AND superseded_at IS NULL`,
      [db.ids.ucm.alice],
    );
    const stored = rows[0]!.row;
    expect(stored).not.toContain(code);
    expect(stored).not.toContain(createHash('sha256').update(code).digest('hex'));
  });

  it('keeps every code it has issued', async () => {
    const code = await requestCode('alice@acme.com');
    await signIn('alice@acme.com', code);
    await requestCode('alice@acme.com');
    const { rows } = await db.pool.query<{ n: string }>(
      `SELECT count(*) AS n FROM email_sign_in_codes WHERE user_communication_method_id = $1`,
      [db.ids.ucm.alice],
    );
    expect(Number(rows[0]!.n)).toBeGreaterThanOrEqual(2);
  });

  it('sends nothing to a dev-OTP user and accepts their authenticator code', async () => {
    const secret = generateDevOtpSecret();
    await db.pool.query(`INSERT INTO dev_otp_enrollments (user_communication_method_id, totp_secret) VALUES ($1, $2)`, [
      db.ids.ucm.noRoles,
      secret,
    ]);
    await router().initiateOtp({ identifier: 'noroles@acme.com' });
    expect(sent).toEqual([]);
    await expect(signIn('noroles@acme.com', generateSync({ secret }))).resolves.toMatchObject({
      userId: db.ids.users.noRoles,
    });
  });

  it('refuses a secret too short to keep codes from being brute-forced', () => {
    expect(() => emailCodeHandler({ codeSecret: 'short', sendCode: async () => {} })).toThrow();
  });
});
