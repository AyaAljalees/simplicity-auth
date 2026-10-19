import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createMethodRouter, InvalidInputError, OtpNotAllowedError, VerificationFailedError } from '../src/index.js';
import type { MethodHandler, ResolvedUser } from '../src/index.js';
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
