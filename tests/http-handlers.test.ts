import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as jose from 'jose';
import { createAuthHandlers } from '../src/http/index.js';
import type { AuthHttpConfig } from '../src/http/index.js';
import { signLoginState, verifyLoginState } from '../src/http/cookies.js';
import { oidcHandler } from '../src/methods/oidc/index.js';
import { VerificationFailedError } from '../src/index.js';
import type { MethodHandler } from '../src/index.js';
import { seedVerifiedDomain } from './helpers/email-domains.js';
import { startTestDb, type TestDb } from './helpers/test-db.js';

let db: TestDb;

beforeAll(async () => {
  db = await startTestDb();
});
afterAll(async () => {
  await db.shutdown();
});

// A mock user-bound OTP handler: code '123456' verifies bob@globex.com
// (seeded → resolves to Bob); anything else fails.
const mockOtp: MethodHandler = {
  async initiate() {
    return { otpSent: true };
  },
  async complete({ identifier, credential }) {
    if (credential !== '123456' || identifier !== 'bob@globex.com') {
      throw new VerificationFailedError('bad code');
    }
    return { userId: db.ids.users.bob, userCommunicationMethodId: db.ids.ucm.bob };
  },
};

function makeConfig(over: Partial<AuthHttpConfig> = {}): AuthHttpConfig {
  return {
    pool: db.pool,
    cookie: { name: 'pn_session', secure: false },
    loginStateSecret: 'test-login-state-secret',
    tenantSlugFromRequest: (request) => request.headers.get('x-tenant-slug'),
    otpHandler: mockOtp,
    ...over,
  };
}

interface ReqOptions {
  slug?: string;
  cookie?: string;
  body?: unknown;
}

interface OptionsBody {
  tenantId: number;
  otpAllowed: boolean;
  authDomains: { authDomainId: number; displayName: string; integrationType: string }[];
}

function req(method: string, url: string, opts: ReqOptions = {}): Request {
  const headers: Record<string, string> = {};
  if (opts.slug) headers['x-tenant-slug'] = opts.slug;
  if (opts.cookie) headers['cookie'] = opts.cookie;
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  return new Request(url, {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

/** Pull a single cookie's value out of a response's Set-Cookie headers. */
function setCookieValue(res: Response, name: string): string | undefined {
  for (const sc of res.headers.getSetCookie()) {
    const pair = sc.split(';')[0] ?? '';
    const eq = pair.indexOf('=');
    if (pair.slice(0, eq) === name) return pair.slice(eq + 1);
  }
  return undefined;
}

describe('createAuthHandlers — sign-in options', () => {
  it('lists a tenant’s OIDC IdPs and whether OTP is offered', async () => {
    const handlers = createAuthHandlers(makeConfig());

    // acme: two IdPs; code sign-in is offered too (SSO is enforced per email domain).
    const acme = await handlers.signInOptions(req('GET', 'https://app.test/auth/sign-in/options', { slug: 'acme' }));
    expect(acme.status).toBe(200);
    const acmeBody = (await acme.json()) as OptionsBody;
    expect(acmeBody.tenantId).toBe(db.ids.tenants.acme);
    expect(acmeBody.otpAllowed).toBe(true);
    expect(acmeBody.authDomains).toHaveLength(2);
    expect(acmeBody.authDomains.map((d) => d.displayName).sort()).toEqual(['Google', 'Microsoft']);
    // integration_params (issuer/clientId) are not leaked to the sign-in UI.
    expect(acmeBody.authDomains[0]).not.toHaveProperty('integrationParams');

    // initech: no IdP, handler present → OTP offered.
    const initech = await handlers.signInOptions(
      req('GET', 'https://app.test/auth/sign-in/options', { slug: 'initech' }),
    );
    const initechBody = (await initech.json()) as OptionsBody;
    expect(initechBody.otpAllowed).toBe(true);
    expect(initechBody.authDomains).toHaveLength(0);
  });

  it('400 when the tenant cannot be resolved, 404 for an unknown slug', async () => {
    const handlers = createAuthHandlers(makeConfig());
    expect((await handlers.signInOptions(req('GET', 'https://app.test/auth/sign-in/options'))).status).toBe(400);
    expect(
      (await handlers.signInOptions(req('GET', 'https://app.test/auth/sign-in/options', { slug: 'nope' }))).status,
    ).toBe(404);
  });
});

describe('createAuthHandlers — OTP', () => {
  it('initiates, completes, mints a session cookie, and that cookie authenticates', async () => {
    const handlers = createAuthHandlers(makeConfig());

    const initiated = await handlers.otpInitiate(
      req('POST', 'https://app.test/auth/otp/initiate', { slug: 'globex', body: { identifier: 'bob@globex.com' } }),
    );
    expect(initiated.status).toBe(200);
    expect(await initiated.json()).toEqual({ otpSent: true });

    const completed = await handlers.otpComplete(
      req('POST', 'https://app.test/auth/otp/complete', {
        slug: 'globex',
        body: { identifier: 'bob@globex.com', credential: '123456' },
      }),
    );
    expect(completed.status).toBe(200);
    const token = setCookieValue(completed, 'pn_session');
    expect(token).toBeTruthy();

    // The minted cookie resolves to Bob (user 3) on the session endpoint.
    const session = await handlers.session(
      req('GET', 'https://app.test/auth/session', { cookie: `pn_session=${token}` }),
    );
    expect(session.status).toBe(200);
    expect(await session.json()).toMatchObject({ authenticated: true, userId: db.ids.users.bob });
  });

  it('ignores an off-site returnTo (open-redirect guard), falling back to the default', async () => {
    const handlers = createAuthHandlers(makeConfig({ returnToDefault: '/home' }));
    for (const evil of ['https://evil.com', '//evil.com', '/\\evil.com']) {
      const res = await handlers.otpComplete(
        req('POST', 'https://app.test/auth/otp/complete', {
          slug: 'globex',
          body: { identifier: 'bob@globex.com', credential: '123456', returnTo: evil },
        }),
      );
      expect(((await res.json()) as { returnTo: string }).returnTo).toBe('/home');
    }
    // A genuine same-origin path is preserved.
    const ok = await handlers.otpComplete(
      req('POST', 'https://app.test/auth/otp/complete', {
        slug: 'globex',
        body: { identifier: 'bob@globex.com', credential: '123456', returnTo: '/dashboard' },
      }),
    );
    expect(((await ok.json()) as { returnTo: string }).returnTo).toBe('/dashboard');
  });

  it.each(['/\t/evil.com', '/\n/evil.com', '/\r/evil.com', '/.//evil.com', '/..//evil.com', ' //evil.com'])(
    'ignores the returnTo %j, which a browser turns into another site',
    async (evil) => {
      const handlers = createAuthHandlers(makeConfig({ returnToDefault: '/home' }));
      const res = await handlers.otpComplete(
        req('POST', 'https://app.test/auth/otp/complete', {
          slug: 'globex',
          body: { identifier: 'bob@globex.com', credential: '123456', returnTo: evil },
        }),
      );
      expect(((await res.json()) as { returnTo: string }).returnTo).toBe('/home');
    },
  );

  it.each([
    ['/a/../dashboard', '/dashboard'],
    ['\t/dashboard', '/dashboard'],
    [' /dashboard', '/dashboard'],
    ['/search?q=a b', '/search?q=a%20b'],
  ])('returns the returnTo %j as the path a browser would reach, %j', async (given, reached) => {
    const handlers = createAuthHandlers(makeConfig({ returnToDefault: '/home' }));
    const res = await handlers.otpComplete(
      req('POST', 'https://app.test/auth/otp/complete', {
        slug: 'globex',
        body: { identifier: 'bob@globex.com', credential: '123456', returnTo: given },
      }),
    );
    expect(((await res.json()) as { returnTo: string }).returnTo).toBe(reached);
  });

  it.each(['https://evil.com/home', '//evil.com', '/.//evil.com', 'home'])(
    'refuses to create handlers whose returnToDefault %j is not a path on this site',
    (returnToDefault) => {
      expect(() => createAuthHandlers(makeConfig({ returnToDefault }))).toThrow(/returnToDefault/);
    },
  );

  it('rejects a bad credential (401) and OTP for an address at an SSO-required domain (403)', async () => {
    const handlers = createAuthHandlers(makeConfig());

    const bad = await handlers.otpComplete(
      req('POST', 'https://app.test/auth/otp/complete', {
        slug: 'globex',
        body: { identifier: 'bob@globex.com', credential: '000000' },
      }),
    );
    expect(bad.status).toBe(401);

    // acme.com requires SSO — refused server-side, on any sub-domain.
    await seedVerifiedDomain(db, db.ids.tenants.acme, 'acme.com', { ssoRequired: true });
    const ssoOnly = await handlers.otpInitiate(
      req('POST', 'https://app.test/auth/otp/initiate', { slug: 'globex', body: { identifier: 'x@acme.com' } }),
    );
    expect(ssoOnly.status).toBe(403);
    expect(await ssoOnly.json()).toMatchObject({ code: 'SSO_REQUIRED' });
  });
});

describe('createAuthHandlers — OIDC end-to-end', () => {
  let issuer: string;
  let authDomainId: number;
  let signIdToken: (claims: jose.JWTPayload) => Promise<void>;
  let fetchImpl: typeof fetch;

  beforeAll(async () => {
    issuer = 'https://mock-idp.oidc.test';
    const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
    const jwk = { ...(await jose.exportJWK(publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' };
    const endpoints = {
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
    };
    let idToken = '';
    signIdToken = async (claims) => {
      idToken = await new jose.SignJWT({ aud: 'mock-client', iss: issuer, ...claims })
        .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey);
    };
    fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return Response.json({
          issuer,
          ...endpoints,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['ES256'],
        });
      }
      if (url === endpoints.jwks_uri) return Response.json({ keys: [jwk] });
      if (url === endpoints.token_endpoint) {
        return Response.json({ access_token: 'at', token_type: 'Bearer', id_token: idToken });
      }
      return new Response('not found', { status: 404 });
    }) as typeof fetch;

    // Seed an auth_domain for globex pointing at the mock IdP (app-init actor for audit).
    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('app.actor_id', '${db.ids.appInit}', true)`);
      const { rows } = await client.query<{ authDomainId: number }>(
        `INSERT INTO auth_domains (tenant_id, display_name, integration_type, integration_params)
         VALUES (${db.ids.tenants.globex}, 'MockIdP', 'oidc', $1::jsonb)
         RETURNING auth_domain_id AS "authDomainId"`,
        [JSON.stringify({ issuer, clientId: 'mock-client', redirectUri: 'https://app.test/auth/oidc/callback' })],
      );
      await client.query('COMMIT');
      // auth_domain_id is bigint → pg returns it as a string.
      authDomainId = Number(rows[0]!.authDomainId);
    } finally {
      client.release();
    }
    // Globex's IdP may vouch for globex.com addresses.
    await seedVerifiedDomain(db, db.ids.tenants.globex, 'globex.com');
  });

  function configWithOidc(): AuthHttpConfig {
    return makeConfig({ oidc: oidcHandler({ fetch: fetchImpl, clientSecret: () => 'mock-secret' }) });
  }

  it('start → IdP redirect + signed login-state, callback → session + return redirect', async () => {
    const handlers = createAuthHandlers(configWithOidc());

    const start = await handlers.oidcStart(
      req('GET', `https://app.test/auth/oidc/start?authDomainId=${authDomainId}&returnTo=/dashboard`),
    );
    expect(start.status).toBe(302);
    const redirect = new URL(start.headers.get('location')!);
    expect(redirect.origin + redirect.pathname).toBe(`${issuer}/authorize`);
    const state = redirect.searchParams.get('state')!;

    const stateCookie = setCookieValue(start, 'pn_session_oidc');
    expect(stateCookie).toBeTruthy();
    // Recover the nonce from the signed cookie so the IdP can mint a matching id_token.
    const login = await verifyLoginState(stateCookie, 'test-login-state-secret', 600);
    expect(login).toMatchObject({ authDomainId, state, returnTo: '/dashboard' });
    await signIdToken({ sub: 'entra-bob', nonce: login!.nonce, email: 'bob@globex.com' });

    const callback = await handlers.oidcCallback(
      req('GET', `https://app.test/auth/oidc/callback?code=test-code&state=${state}`, {
        cookie: `pn_session_oidc=${stateCookie}`,
      }),
    );
    expect(callback.status).toBe(302);
    expect(callback.headers.get('location')).toBe('/dashboard');
    const sessionToken = setCookieValue(callback, 'pn_session');
    expect(sessionToken).toBeTruthy();
    // login-state cookie is cleared.
    const cleared = callback.headers.getSetCookie().find((c) => c.startsWith('pn_session_oidc='));
    expect(cleared).toContain('Max-Age=0');

    // The session belongs to Bob (user 3, matched by email → ucm 2).
    const session = await handlers.session(
      req('GET', 'https://app.test/auth/session', { cookie: `pn_session=${sessionToken}` }),
    );
    expect(await session.json()).toMatchObject({ authenticated: true, userId: db.ids.users.bob });
  });

  it('start leaves an unsafe returnTo out of the login state it signs', async () => {
    const handlers = createAuthHandlers(configWithOidc());
    for (const evil of ['//evil.com', '/\t/evil.com', '/.//evil.com']) {
      const start = await handlers.oidcStart(
        req(
          'GET',
          `https://app.test/auth/oidc/start?authDomainId=${authDomainId}&returnTo=${encodeURIComponent(evil)}`,
        ),
      );
      expect(start.status).toBe(302);
      const login = await verifyLoginState(setCookieValue(start, 'pn_session_oidc')!, 'test-login-state-secret', 600);
      expect(login).not.toHaveProperty('returnTo');
    }
  });

  it('callback ignores an unsafe returnTo carried in a validly signed login state', async () => {
    const handlers = createAuthHandlers(makeConfig({ returnToDefault: '/home', oidc: configWithOidc().oidc }));
    const start = await handlers.oidcStart(req('GET', `https://app.test/auth/oidc/start?authDomainId=${authDomainId}`));
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const login = await verifyLoginState(setCookieValue(start, 'pn_session_oidc')!, 'test-login-state-secret', 600);
    const tampered = await signLoginState({ ...login!, returnTo: '/\t/evil.com' }, 'test-login-state-secret');
    await signIdToken({ sub: 'entra-bob', nonce: login!.nonce, email: 'bob@globex.com' });

    const callback = await handlers.oidcCallback(
      req('GET', `https://app.test/auth/oidc/callback?code=test-code&state=${state}`, {
        cookie: `pn_session_oidc=${tampered}`,
      }),
    );

    expect(callback.status).toBe(302);
    expect(callback.headers.get('location')).toBe('/home');
  });

  it('callback with a missing/forged login-state cookie is rejected (400)', async () => {
    const handlers = createAuthHandlers(configWithOidc());
    const noCookie = await handlers.oidcCallback(req('GET', 'https://app.test/auth/oidc/callback?code=c&state=s'));
    expect(noCookie.status).toBe(400);
    const forged = await handlers.oidcCallback(
      req('GET', 'https://app.test/auth/oidc/callback?code=c&state=s', { cookie: 'pn_session_oidc=forged.sig' }),
    );
    expect(forged.status).toBe(400);
  });

  it('OIDC endpoints 404 when OIDC is not configured', async () => {
    const handlers = createAuthHandlers(makeConfig()); // no oidc
    expect((await handlers.oidcStart(req('GET', 'https://app.test/auth/oidc/start?authDomainId=1'))).status).toBe(404);
    expect((await handlers.oidcCallback(req('GET', 'https://app.test/auth/oidc/callback'))).status).toBe(404);
  });
});

describe('createAuthHandlers — session, sign-out, routing', () => {
  it('session is 401 without a token; sign-out revokes and clears the cookie', async () => {
    const handlers = createAuthHandlers(makeConfig());

    expect((await handlers.session(req('GET', 'https://app.test/auth/session'))).status).toBe(401);

    // Mint a session via OTP, then sign out.
    const completed = await handlers.otpComplete(
      req('POST', 'https://app.test/auth/otp/complete', {
        slug: 'globex',
        body: { identifier: 'bob@globex.com', credential: '123456' },
      }),
    );
    const token = setCookieValue(completed, 'pn_session')!;

    const signOut = await handlers.signOut(
      req('POST', 'https://app.test/auth/sign-out', { cookie: `pn_session=${token}` }),
    );
    expect(signOut.status).toBe(200);
    expect(signOut.headers.getSetCookie().find((c) => c.startsWith('pn_session='))).toContain('Max-Age=0');

    // The revoked token no longer authenticates.
    const after = await handlers.session(
      req('GET', 'https://app.test/auth/session', { cookie: `pn_session=${token}` }),
    );
    expect(after.status).toBe(401);
  });

  it('handle() dispatches by method+path suffix and returns null for non-auth routes', async () => {
    const handlers = createAuthHandlers(makeConfig());

    const session = await handlers.handle(req('GET', 'https://app.test/api/auth/session'));
    expect(session?.status).toBe(401);

    const options = await handlers.handle(req('GET', 'https://app.test/api/auth/sign-in/options', { slug: 'globex' }));
    expect(options?.status).toBe(200);

    expect(await handlers.handle(req('GET', 'https://app.test/api/widgets'))).toBeNull();
    // Wrong method on a known path also falls through.
    expect(await handlers.handle(req('POST', 'https://app.test/api/auth/session'))).toBeNull();
  });
});
