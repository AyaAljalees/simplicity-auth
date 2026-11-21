import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createTwilioVerifyClient } from '@smplcty/twilio';
import {
  createMethodRouter,
  DeliveryUnavailableError,
  InvalidInputError,
  OTP_OUTAGE_WINDOW_SECONDS,
  OtpNotAllowedError,
  UnknownIdentifierError,
  VerificationFailedError,
} from '../src/index.js';
import type { Logger, MethodHandler, ResolvedUser } from '../src/index.js';
import { emailCodeHandler } from '../src/methods/email-code/index.js';
import { twilioVerifyHandler } from '../src/methods/twilio/index.js';
import { startTestDb, type TestDb } from './helpers/test-db.js';

// The resolved user the stub OTP handler returns. Populated per-describe from
// the seeded data (Bob) once the template is cloned; the gating tests only
// assert that the router passes the handler's result straight through.
let stubUser: ResolvedUser;

function stubHandler(): MethodHandler & { initiate: ReturnType<typeof vi.fn>; complete: ReturnType<typeof vi.fn> } {
  return {
    initiate: vi.fn(async () => ({ otpSent: true as const })),
    complete: vi.fn(async () => stubUser),
  };
}

// Fixture (see seed-test-data.sql):
//   acme    (slug 'acme')    → IdPs Microsoft + Google
//   globex  (slug 'globex')  → IdP Okta
//   initech (slug 'initech') → no IdP
describe('createMethodRouter — discovery (signInOptions)', () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await startTestDb();
    stubUser = { userId: db.ids.users.bob, userCommunicationMethodId: db.ids.ucm.bob };
  });
  afterAll(async () => {
    await db.shutdown();
  });

  it('multi-IdP tenant → all IdPs, OTP offered alongside', async () => {
    const router = createMethodRouter({ db: db.pool, otpHandler: stubHandler() });
    const opts = await router.signInOptions({ tenantSlug: 'acme' });
    expect(opts?.tenantId).toBe(db.ids.tenants.acme);
    expect(opts?.authDomains.map((d) => d.displayName).sort()).toEqual(['Google', 'Microsoft']);
    // Code sign-in is offered on every tenant; SSO is enforced per email domain.
    expect(opts?.otpAllowed).toBe(true);
  });

  it('single-IdP tenant with OTP allowed → one IdP, OTP allowed', async () => {
    const router = createMethodRouter({ db: db.pool, otpHandler: stubHandler() });
    const opts = await router.signInOptions({ tenantSlug: 'globex' });
    expect(opts?.authDomains).toHaveLength(1);
    expect(opts?.authDomains[0]?.displayName).toBe('Okta');
    expect(opts?.authDomains[0]?.integrationType).toBe('oidc');
    expect(opts?.otpAllowed).toBe(true);
  });

  it('no-IdP tenant → zero IdPs, OTP allowed', async () => {
    const router = createMethodRouter({ db: db.pool, otpHandler: stubHandler() });
    const opts = await router.signInOptions({ tenantSlug: 'initech' });
    expect(opts?.authDomains).toEqual([]);
    expect(opts?.otpAllowed).toBe(true);
  });

  it('otpAllowed is false when no otpHandler is configured', async () => {
    const router = createMethodRouter({ db: db.pool });
    const opts = await router.signInOptions({ tenantSlug: 'globex' });
    expect(opts?.otpAllowed).toBe(false);
  });

  it('returns null for an unknown slug', async () => {
    const router = createMethodRouter({ db: db.pool });
    expect(await router.signInOptions({ tenantSlug: 'nope' })).toBeNull();
  });
});

describe('createMethodRouter — OTP', () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await startTestDb();
    stubUser = { userId: db.ids.users.bob, userCommunicationMethodId: db.ids.ucm.bob };
  });
  afterAll(async () => {
    await db.shutdown();
  });

  it('runs both OTP phases through the handler', async () => {
    const otp = stubHandler();
    const router = createMethodRouter({ db: db.pool, otpHandler: otp });
    await router.initiateOtp({ identifier: 'a@b.com' }); // globex
    expect(otp.initiate).toHaveBeenCalledOnce();
    expect(await router.completeOtp({ identifier: 'a@b.com', credential: '123' })).toEqual(stubUser);
  });

  it('refuses OTP when no otpHandler is configured', async () => {
    const router = createMethodRouter({ db: db.pool });
    await expect(router.initiateOtp({ identifier: 'a@b.com' })).rejects.toBeInstanceOf(OtpNotAllowedError);
  });

  it('throws InvalidInputError on bad inputs', async () => {
    const router = createMethodRouter({ db: db.pool, otpHandler: stubHandler() });
    await expect(router.initiateOtp({ identifier: '' })).rejects.toBeInstanceOf(InvalidInputError);
    await expect(router.completeOtp({ identifier: 'a@b.com', credential: '' })).rejects.toBeInstanceOf(
      InvalidInputError,
    );
  });
});

describe('twilioVerifyHandler via router.completeOtp', () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await startTestDb();
    stubUser = { userId: db.ids.users.bob, userCommunicationMethodId: db.ids.ucm.bob };
  });
  afterAll(async () => {
    await db.shutdown();
  });

  function fakeClient(approve: boolean) {
    return {
      sendVerificationCode: vi.fn(async () => true),
      verifyVerificationCode: vi.fn(async () => approve),
    };
  }

  it('resolves the user on an approved code', async () => {
    const router = createMethodRouter({
      db: db.pool,
      otpHandler: twilioVerifyHandler({ client: fakeClient(true) }),
    });
    // alice@acme.com resolves to Alice.
    const user = await router.completeOtp({
      identifier: 'alice@acme.com',
      credential: '123456',
    });
    expect(user).toEqual({ userId: db.ids.users.alice, userCommunicationMethodId: db.ids.ucm.alice });
  });

  it('throws VerificationFailedError on a rejected code', async () => {
    const router = createMethodRouter({
      db: db.pool,
      otpHandler: twilioVerifyHandler({ client: fakeClient(false) }),
    });
    await expect(router.completeOtp({ identifier: 'alice@acme.com', credential: '000000' })).rejects.toBeInstanceOf(
      VerificationFailedError,
    );
  });
});

describe('createMethodRouter — a failed send answers as for an unknown identifier (#36)', () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await startTestDb();
    stubUser = { userId: db.ids.users.bob, userCommunicationMethodId: db.ids.ucm.bob };
  });
  afterAll(async () => {
    await db.shutdown();
  });
  // The email handler stops sending after EMAIL_CODE_MAX_SENDS in the window, so each test starts with an empty one.
  beforeEach(async () => {
    await db.pool.query(
      `UPDATE email_sign_in_codes SET created_at = created_at - interval '1 day', superseded_at = now()`,
    );
  });

  const KNOWN = 'bob@globex.com';
  const STRANGER = 'nobody-36@globex.com';

  function recordingLogger(): Logger & { entries: { data: Record<string, unknown>; msg: string }[] } {
    const entries: { data: Record<string, unknown>; msg: string }[] = [];
    const record = (data: Record<string, unknown>, msg: string) => void entries.push({ data, msg });
    return { entries, debug: record, info: record, warn: record, error: record };
  }

  const failingEmail = () =>
    emailCodeHandler({
      codeSecret: 'test-email-code-secret-at-least-32-bytes',
      sendCode: async ({ to }) => {
        throw Object.assign(new Error(`Email address is not verified: ${to}`), { name: 'MessageRejected' });
      },
    });

  const failingTwilio = () =>
    twilioVerifyHandler({
      client: {
        sendVerificationCode: async () => {
          throw new TypeError('fetch failed');
        },
        verifyVerificationCode: async () => false,
      },
    });

  for (const [name, handler] of [
    ['email code', failingEmail],
    ['Twilio Verify', failingTwilio],
  ] as const) {
    it(`${name}: a registered contact gets the same answer as a stranger`, async () => {
      const router = createMethodRouter({ db: db.pool, otpHandler: handler() });
      const known = await router.initiateOtp({ identifier: KNOWN }).catch((err: unknown) => err);
      const stranger = await router.initiateOtp({ identifier: STRANGER }).catch((err: unknown) => err);
      expect(known).toEqual({ otpSent: true });
      expect(known).toEqual(stranger);
    });
  }

  it('reports the failure to the logger with the kind, never the identifier', async () => {
    const logger = recordingLogger();
    const router = createMethodRouter({ db: db.pool, otpHandler: failingEmail(), logger });
    await router.initiateOtp({ identifier: KNOWN });
    expect(logger.entries).toHaveLength(1);
    expect(logger.entries[0]?.data).toEqual({ kind: 'email', error: 'MessageRejected' });
    expect(JSON.stringify(logger.entries)).toMatch(/MessageRejected/);
    expect(JSON.stringify(logger.entries)).not.toContain(KNOWN);
  });

  it("keeps a handler's own refusal, which the handler means to show", async () => {
    const refusing: MethodHandler = {
      initiate: async () => {
        throw new InvalidInputError('phone must be E.164');
      },
      complete: async () => stubUser,
    };
    const logger = recordingLogger();
    const router = createMethodRouter({ db: db.pool, otpHandler: refusing, logger });
    await expect(router.initiateOtp({ identifier: '5551234' })).rejects.toBeInstanceOf(InvalidInputError);
    expect(logger.entries).toEqual([]);
  });

  it('a logger that throws does not bring the difference back', async () => {
    const broken: Logger = {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {
        throw new Error('log transport down');
      },
    };
    const router = createMethodRouter({ db: db.pool, otpHandler: failingEmail(), logger: broken });
    expect(await router.initiateOtp({ identifier: KNOWN })).toEqual({ otpSent: true });
  });

  it("logs the error's code when it is a short token, such as a database SQLSTATE", async () => {
    const logger = recordingLogger();
    const dbDown = emailCodeHandler({
      codeSecret: 'test-email-code-secret-at-least-32-bytes',
      sendCode: async ({ to }) => {
        throw Object.assign(new Error(`terminating connection for ${to}`), { name: 'error', code: '57P01' });
      },
    });
    const router = createMethodRouter({ db: db.pool, otpHandler: dbDown, logger });
    await router.initiateOtp({ identifier: KNOWN });
    expect(logger.entries[0]?.data).toEqual({ kind: 'email', error: 'error', code: '57P01' });
  });

  it("leaves out a code that isn't a short token, since it could carry the address", async () => {
    const logger = recordingLogger();
    const odd = emailCodeHandler({
      codeSecret: 'test-email-code-secret-at-least-32-bytes',
      sendCode: async ({ to }) => {
        throw Object.assign(new Error('rejected'), { name: 'ProviderError', code: `rejected ${to}` });
      },
    });
    const router = createMethodRouter({ db: db.pool, otpHandler: odd, logger });
    await router.initiateOtp({ identifier: KNOWN });
    expect(logger.entries[0]?.data).toEqual({ kind: 'email', error: 'ProviderError' });
  });

  it('leaves out a code shaped like a phone number', async () => {
    const logger = recordingLogger();
    const phoneCode = emailCodeHandler({
      codeSecret: 'test-email-code-secret-at-least-32-bytes',
      sendCode: async () => {
        throw Object.assign(new Error('rejected'), { name: 'ProviderError', code: '15551234567' });
      },
    });
    const router = createMethodRouter({ db: db.pool, otpHandler: phoneCode, logger });
    await router.initiateOtp({ identifier: KNOWN });
    expect(logger.entries[0]?.data).toEqual({ kind: 'email', error: 'ProviderError' });
  });

  it("a database failure in the owner's SSO check, which runs only for a registered contact, answers as for a stranger", async () => {
    // The per-user SSO lookup reads the user's email domains; fail just that query.
    const flaky = {
      query: (text: string, values?: unknown[]) =>
        text.includes('substring(ucm.code')
          ? Promise.reject(Object.assign(new Error('terminating connection'), { code: '57P01' }))
          : db.pool.query(text, values),
    } as unknown as typeof db.pool;
    const logger = recordingLogger();
    const sent: string[] = [];
    const email = emailCodeHandler({
      codeSecret: 'test-email-code-secret-at-least-32-bytes',
      sendCode: async ({ to }) => void sent.push(to),
    });
    const router = createMethodRouter({ db: flaky, otpHandler: email, logger });
    const known = await router.initiateOtp({ identifier: KNOWN }).catch((err: unknown) => err);
    const stranger = await router.initiateOtp({ identifier: STRANGER }).catch((err: unknown) => err);
    expect(known).toEqual({ otpSent: true });
    expect(known).toEqual(stranger);
    expect(sent).toEqual([]);
    expect(logger.entries[0]?.data).toEqual({ kind: 'email', error: 'Error', code: '57P01' });
  });

  it('keeps an error name that could carry the address out of the log', async () => {
    const logger = recordingLogger();
    const named = emailCodeHandler({
      codeSecret: 'test-email-code-secret-at-least-32-bytes',
      sendCode: async ({ to }) => {
        throw Object.assign(new Error('rejected'), { name: `Rejected<${to}>` });
      },
    });
    const router = createMethodRouter({ db: db.pool, otpHandler: named, logger });
    await router.initiateOtp({ identifier: KNOWN });
    expect(logger.entries).toHaveLength(1);
    expect(JSON.stringify(logger.entries)).not.toContain(KNOWN);
  });

  it('still refuses openly where a refusal is meant to show', async () => {
    const router = createMethodRouter({ db: db.pool, otpHandler: { phone: failingTwilio() } });
    await expect(router.initiateOtp({ identifier: KNOWN })).rejects.toBeInstanceOf(OtpNotAllowedError);
    await expect(router.initiateOtp({ identifier: '' })).rejects.toBeInstanceOf(InvalidInputError);
  });
});

describe('createMethodRouter — outages and reveal mode (#36)', () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await startTestDb();
  });
  afterAll(async () => {
    await db.shutdown();
  });
  beforeEach(async () => {
    await db.pool.query(
      `UPDATE email_sign_in_codes SET created_at = created_at - interval '1 day', superseded_at = now()`,
    );
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const KNOWN = 'bob@globex.com';
  const STRANGER = 'nobody-36@globex.com';
  const PHONE_STRANGER = '+15550000036';
  const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

  /** A real @smplcty/twilio client whose every Twilio answer is `status` with `body`. */
  function twilioAnswering(status: number, body: unknown = {}) {
    const fetch = vi.fn(
      async () => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }),
    ) as unknown as typeof globalThis.fetch;
    return twilioVerifyHandler({
      client: createTwilioVerifyClient({
        accountSid: 'AC00000000000000000000000000000000',
        authToken: 'test',
        serviceSid: 'VA00000000000000000000000000000000',
        fetch,
      }),
    });
  }

  const outcome = (p: Promise<unknown>) => p.catch((err: unknown) => err);

  it('a Twilio outage is answered honestly, and the same for a stranger, for the outage window', async () => {
    const router = createMethodRouter({
      db: db.pool,
      otpHandler: twilioAnswering(401, { code: 20003 }),
      logger: silent,
    });

    const known = await outcome(router.initiateOtp({ identifier: KNOWN }));
    expect(known).toBeInstanceOf(DeliveryUnavailableError);
    expect((known as DeliveryUnavailableError).retryAfterSeconds).toBe(OTP_OUTAGE_WINDOW_SECONDS);

    const stranger = await outcome(router.initiateOtp({ identifier: STRANGER }));
    expect(stranger).toBeInstanceOf(DeliveryUnavailableError);
    expect((stranger as DeliveryUnavailableError).code).toBe((known as DeliveryUnavailableError).code);
  });

  it('closes the window after OTP_OUTAGE_WINDOW_SECONDS', async () => {
    const router = createMethodRouter({ db: db.pool, otpHandler: twilioAnswering(503), logger: silent });
    const start = Date.now();
    await outcome(router.initiateOtp({ identifier: KNOWN }));

    vi.spyOn(Date, 'now').mockReturnValue(start + (OTP_OUTAGE_WINDOW_SECONDS - 1) * 1000);
    expect(await outcome(router.initiateOtp({ identifier: STRANGER }))).toBeInstanceOf(DeliveryUnavailableError);

    vi.spyOn(Date, 'now').mockReturnValue(start + (OTP_OUTAGE_WINDOW_SECONDS + 1) * 1000);
    expect(await router.initiateOtp({ identifier: STRANGER })).toEqual({ otpSent: true });
  });

  it('keeps the window to the kind that failed', async () => {
    const router = createMethodRouter({
      db: db.pool,
      otpHandler: { email: twilioAnswering(500), phone: twilioAnswering(200, { status: 'pending' }) },
      logger: silent,
    });
    await outcome(router.initiateOtp({ identifier: KNOWN }));
    expect(await router.initiateOtp({ identifier: PHONE_STRANGER })).toEqual({ otpSent: true });
  });

  it('still hides a refusal of one number, which says nothing about an outage', async () => {
    const router = createMethodRouter({
      db: db.pool,
      otpHandler: twilioAnswering(400, { code: 21211 }),
      logger: silent,
    });
    expect(await router.initiateOtp({ identifier: KNOWN })).toEqual({ otpSent: true });
    expect(await router.initiateOtp({ identifier: STRANGER })).toEqual({ otpSent: true });
  });

  it('a Twilio outage on a check is not reported as a wrong code, for anyone', async () => {
    const router = createMethodRouter({ db: db.pool, otpHandler: twilioAnswering(500), logger: silent });
    const known = await outcome(router.completeOtp({ identifier: KNOWN, credential: '123456' }));
    expect(known).toBeInstanceOf(DeliveryUnavailableError);
    const stranger = await outcome(router.completeOtp({ identifier: STRANGER, credential: '123456' }));
    expect(stranger).toBeInstanceOf(DeliveryUnavailableError);
  });

  it('an outage on checks does not stop sends, and the reverse', async () => {
    let checksDown = true;
    const handler: MethodHandler = {
      resolveUser: async () => null,
      initiate: async () => ({ otpSent: true }),
      complete: async () => {
        if (checksDown) throw new DeliveryUnavailableError();
        throw new VerificationFailedError();
      },
    };
    const router = createMethodRouter({ db: db.pool, otpHandler: handler, logger: silent });
    await outcome(router.completeOtp({ identifier: KNOWN, credential: '123456' }));
    checksDown = false;
    expect(await router.initiateOtp({ identifier: KNOWN })).toEqual({ otpSent: true });
  });

  it("an app's sendCode can mark an outage by throwing DeliveryUnavailableError", async () => {
    const router = createMethodRouter({
      db: db.pool,
      otpHandler: emailCodeHandler({
        codeSecret: 'test-email-code-secret-at-least-32-bytes',
        sendCode: async () => {
          throw new DeliveryUnavailableError(undefined, {
            cause: Object.assign(new Error('x'), { name: 'Throttling' }),
          });
        },
      }),
      logger: silent,
    });
    expect(await outcome(router.initiateOtp({ identifier: KNOWN }))).toBeInstanceOf(DeliveryUnavailableError);
    expect(await outcome(router.initiateOtp({ identifier: STRANGER }))).toBeInstanceOf(DeliveryUnavailableError);
  });

  it('logs the outage with the kind and the provider code, never the identifier', async () => {
    const entries: { data: Record<string, unknown>; msg: string }[] = [];
    const record = (data: Record<string, unknown>, msg: string) => void entries.push({ data, msg });
    const router = createMethodRouter({
      db: db.pool,
      otpHandler: twilioAnswering(401, { code: 20003 }),
      logger: { debug: record, info: record, warn: record, error: record },
    });
    await outcome(router.initiateOtp({ identifier: KNOWN }));
    expect(entries).toEqual([
      {
        data: { kind: 'email', error: 'TwilioUnavailableError', code: 'TWILIO_UNAVAILABLE' },
        msg: 'OTP initiate unavailable',
      },
    ]);
    expect(JSON.stringify(entries)).not.toContain(KNOWN);
  });

  it('logs a numeric provider code, and one on the cause', async () => {
    const entries: Record<string, unknown>[] = [];
    const record = (data: Record<string, unknown>) => void entries.push(data);
    const logger = { debug: record, info: record, warn: record, error: record };
    const failing = (err: unknown) =>
      createMethodRouter({
        db: db.pool,
        logger,
        otpHandler: emailCodeHandler({
          codeSecret: 'test-email-code-secret-at-least-32-bytes',
          sendCode: async () => {
            throw err;
          },
        }),
      });
    await failing(Object.assign(new Error('x'), { name: 'RestException', code: 21608 })).initiateOtp({
      identifier: KNOWN,
    });
    await failing(new TypeError('fetch failed', { cause: { code: 'ECONNRESET' } })).initiateOtp({ identifier: KNOWN });
    expect(entries).toEqual([
      { kind: 'email', error: 'RestException', code: '21608' },
      { kind: 'email', error: 'TypeError', code: 'ECONNRESET' },
    ]);
  });

  it('an error whose name is not a string is still answered as for a stranger', async () => {
    const router = createMethodRouter({
      db: db.pool,
      logger: silent,
      otpHandler: emailCodeHandler({
        codeSecret: 'test-email-code-secret-at-least-32-bytes',
        sendCode: async () => {
          throw Object.assign(new Error('x'), { name: Symbol('odd') });
        },
      }),
    });
    expect(await router.initiateOtp({ identifier: KNOWN })).toEqual({ otpSent: true });
  });

  it('without a logger, failures go to the console', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const router = createMethodRouter({ db: db.pool, otpHandler: twilioAnswering(500) });
    await outcome(router.initiateOtp({ identifier: KNOWN }));
    expect(errorSpy).toHaveBeenCalledWith('OTP initiate unavailable', expect.objectContaining({ kind: 'email' }));
    expect(JSON.stringify(errorSpy.mock.calls)).not.toContain(KNOWN);
  });

  describe('revealUnknownIdentifiers', () => {
    const working = () =>
      emailCodeHandler({ codeSecret: 'test-email-code-secret-at-least-32-bytes', sendCode: async () => {} });

    it('refuses an identifier no account uses', async () => {
      const router = createMethodRouter({ db: db.pool, otpHandler: working(), revealUnknownIdentifiers: true });
      await expect(router.initiateOtp({ identifier: STRANGER })).rejects.toBeInstanceOf(UnknownIdentifierError);
      expect(await router.initiateOtp({ identifier: KNOWN })).toEqual({ otpSent: true });
    });

    it('says a failed send failed, and opens no window for anyone else', async () => {
      const router = createMethodRouter({
        db: db.pool,
        logger: silent,
        revealUnknownIdentifiers: true,
        otpHandler: emailCodeHandler({
          codeSecret: 'test-email-code-secret-at-least-32-bytes',
          sendCode: async () => {
            throw Object.assign(new Error('rejected'), { name: 'MessageRejected' });
          },
        }),
      });
      await expect(router.initiateOtp({ identifier: KNOWN })).rejects.toBeInstanceOf(DeliveryUnavailableError);
      await expect(router.initiateOtp({ identifier: STRANGER })).rejects.toBeInstanceOf(UnknownIdentifierError);
    });

    it('says a Twilio outage is an outage', async () => {
      const router = createMethodRouter({
        db: db.pool,
        logger: silent,
        revealUnknownIdentifiers: true,
        otpHandler: twilioAnswering(500),
      });
      await expect(router.initiateOtp({ identifier: KNOWN })).rejects.toBeInstanceOf(DeliveryUnavailableError);
      await expect(router.initiateOtp({ identifier: STRANGER })).rejects.toBeInstanceOf(UnknownIdentifierError);
    });
  });
});
