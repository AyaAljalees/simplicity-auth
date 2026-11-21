import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as jose from 'jose';
import { createAuthHandlers } from '../src/http/index.js';
import type { AuthHttpConfig } from '../src/http/index.js';
import { signLoginState, verifyLoginState } from '../src/http/cookies.js';
import { oidcHandler } from '../src/methods/oidc/index.js';
import { emailCodeHandler } from '../src/methods/email-code/index.js';
import { SignInRefusedError, VerificationFailedError } from '../src/index.js';
import type { MethodHandler, ResolvedUser } from '../src/index.js';
import type { SignInMethod } from '../src/http/index.js';
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
    expect(await ssoOnly.json()).toMatchObject({ code: 'SSO_REQUIRED', domain: 'acme.com' });

    const options = await handlers.signInOptions(req('GET', 'https://app.test/auth/sign-in/options', { slug: 'acme' }));
    expect(await options.json()).toMatchObject({ ssoRequired: true });
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

  describe('with a sign-in error path', () => {
    const errorConfig = (path = '/sign-in/error') =>
      makeConfig({ signInErrorPath: path, oidc: oidcHandler({ fetch: fetchImpl, clientSecret: () => 'mock-secret' }) });

    async function callbackAs(config: AuthHttpConfig, email: string): Promise<Response> {
      const handlers = createAuthHandlers(config);
      const start = await handlers.oidcStart(
        req('GET', `https://app.test/auth/oidc/start?authDomainId=${authDomainId}`),
      );
      const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
      const stateCookie = setCookieValue(start, 'pn_session_oidc')!;
      const login = await verifyLoginState(stateCookie, 'test-login-state-secret', 600);
      await signIdToken({ sub: `sub-${email}`, nonce: login!.nonce, email });
      return handlers.oidcCallback(
        req('GET', `https://app.test/auth/oidc/callback?code=test-code&state=${state}`, {
          cookie: `pn_session_oidc=${stateCookie}`,
        }),
      );
    }

    it('sends a refused sign-in to the error path with only its code', async () => {
      const res = await callbackAs(errorConfig(), 'bob@unverified.example');

      expect(res.status).toBe(302);
      expect(res.headers.get('location')).toBe('/sign-in/error?error=EMAIL_DOMAIN_NOT_VERIFIED');
      expect(setCookieValue(res, 'pn_session')).toBeFalsy();
      const cleared = res.headers.getSetCookie().find((c) => c.startsWith('pn_session_oidc='));
      expect(cleared).toContain('Max-Age=0');
    });

    it('sends a missing or forged login state to the error path', async () => {
      const handlers = createAuthHandlers(errorConfig());
      const forged = await handlers.oidcCallback(
        req('GET', 'https://app.test/auth/oidc/callback?code=c&state=s', { cookie: 'pn_session_oidc=forged.sig' }),
      );

      expect(forged.status).toBe(302);
      expect(forged.headers.get('location')).toBe('/sign-in/error?error=INVALID_LOGIN_STATE');
    });

    it('sends an unknown auth domain at the start to the error path', async () => {
      const handlers = createAuthHandlers(errorConfig());
      const res = await handlers.oidcStart(req('GET', 'https://app.test/auth/oidc/start?authDomainId=999999'));

      expect(res.status).toBe(302);
      expect(res.headers.get('location')).toBe('/sign-in/error?error=UNKNOWN_AUTH_DOMAIN');
    });

    it('leaves a sign-in in progress alone when a forged callback fails', async () => {
      const handlers = createAuthHandlers(errorConfig());
      const forged = await handlers.oidcCallback(
        req('GET', 'https://app.test/auth/oidc/callback?code=c&state=s', { cookie: 'pn_session_oidc=forged.sig' }),
      );

      expect(forged.headers.getSetCookie().find((c) => c.startsWith('pn_session_oidc='))).toBeUndefined();
    });

    it('sends a callback for an auth domain that no longer exists to the error path', async () => {
      const handlers = createAuthHandlers(errorConfig());
      const stateCookie = await signLoginState(
        { authDomainId: 999999, state: 's', nonce: 'n', codeVerifier: 'v' },
        'test-login-state-secret',
      );

      const res = await handlers.oidcCallback(
        req('GET', 'https://app.test/auth/oidc/callback?code=c&state=s', { cookie: `pn_session_oidc=${stateCookie}` }),
      );

      expect(res.headers.get('location')).toBe('/sign-in/error?error=UNKNOWN_AUTH_DOMAIN');
    });

    it('sends a bad start request to the error path', async () => {
      const handlers = createAuthHandlers(errorConfig());
      const res = await handlers.oidcStart(req('GET', 'https://app.test/auth/oidc/start?authDomainId=abc'));

      expect(res.headers.get('location')).toBe('/sign-in/error?error=INVALID_INPUT');
    });

    it('sends an unexpected failure to the error path with a generic code', async () => {
      const broken = async (): Promise<never> => {
        throw new TypeError('network down');
      };
      const handlers = createAuthHandlers(
        makeConfig({ signInErrorPath: '/sign-in/error', oidc: { initiate: broken, complete: broken } }),
      );

      const res = await handlers.oidcStart(req('GET', `https://app.test/auth/oidc/start?authDomainId=${authDomainId}`));

      expect(res.headers.get('location')).toBe('/sign-in/error?error=SIGN_IN_FAILED');
    });

    it('sends both OIDC endpoints to the error path when OIDC is not configured', async () => {
      const handlers = createAuthHandlers(makeConfig({ signInErrorPath: '/sign-in/error' }));

      const start = await handlers.oidcStart(req('GET', 'https://app.test/auth/oidc/start?authDomainId=1'));
      const callback = await handlers.oidcCallback(req('GET', 'https://app.test/auth/oidc/callback'));

      expect(start.headers.get('location')).toBe('/sign-in/error?error=OIDC_NOT_CONFIGURED');
      expect(callback.headers.get('location')).toBe('/sign-in/error?error=OIDC_NOT_CONFIGURED');
    });

    it("keeps the error path's fragment after the code", async () => {
      const res = await callbackAs(errorConfig('/sign-in#sso'), 'bob@unverified.example');

      expect(res.headers.get('location')).toBe('/sign-in?error=EMAIL_DOMAIN_NOT_VERIFIED#sso');
    });

    it("keeps the error path's own query", async () => {
      const res = await callbackAs(errorConfig('/sign-in?view=sso'), 'bob@unverified.example');

      expect(res.headers.get('location')).toBe('/sign-in?view=sso&error=EMAIL_DOMAIN_NOT_VERIFIED');
    });

    it('refuses an error path that would leave the site', () => {
      expect(() => createAuthHandlers(errorConfig('//evil.example'))).toThrow();
    });

    it('still answers JSON when no error path is configured', async () => {
      const res = await callbackAs(configWithOidc(), 'bob@unverified.example');

      expect(res.status).toBe(403);
      expect(await res.json()).toMatchObject({ code: 'EMAIL_DOMAIN_NOT_VERIFIED' });
    });
  });

  describe('telling the app why a sign-in failed', () => {
    type Failure = Parameters<NonNullable<AuthHttpConfig['onSignInFailure']>>[0];

    function reporting(fetchOverride: typeof fetch = fetchImpl) {
      const failures: Failure[] = [];
      const config = makeConfig({
        signInErrorPath: '/sign-in',
        onSignInFailure: (failure) => {
          failures.push(failure);
        },
        oidc: oidcHandler({ fetch: fetchOverride, clientSecret: () => 'mock-secret' }),
      });
      return { handlers: createAuthHandlers(config), failures };
    }

    async function startAndCallBack(handlers: ReturnType<typeof createAuthHandlers>, query: (state: string) => string) {
      const start = await handlers.oidcStart(
        req('GET', `https://app.test/auth/oidc/start?authDomainId=${authDomainId}`),
      );
      const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
      const stateCookie = setCookieValue(start, 'pn_session_oidc')!;
      const login = await verifyLoginState(stateCookie, 'test-login-state-secret', 600);
      return {
        login: login!,
        callback: () =>
          handlers.oidcCallback(
            req('GET', `https://app.test/auth/oidc/callback?${query(state)}`, {
              cookie: `pn_session_oidc=${stateCookie}`,
            }),
          ),
      };
    }

    it('reports the code, the auth domain and a detail the person never sees', async () => {
      const { handlers, failures } = reporting();
      const flow = await startAndCallBack(handlers, (state) => `code=c&state=${state}`);
      await signIdToken({ sub: 'sub-ghost', nonce: flow.login.nonce, email: 'ghost@globex.com' });

      const res = await flow.callback();

      expect(res.headers.get('location')).toBe('/sign-in?error=VERIFICATION_FAILED');
      expect(failures).toHaveLength(1);
      expect(failures[0]).toMatchObject({ code: 'VERIFICATION_FAILED', authDomainId });
      expect(failures[0]!.detail).toContain('ghost@globex.com');
    });

    it("passes on the identity provider's own refusal at the sign-in", async () => {
      const { handlers, failures } = reporting();
      const flow = await startAndCallBack(
        handlers,
        (state) =>
          `error=access_denied&error_description=${encodeURIComponent('AADSTS50105: not assigned to a role')}&state=${state}`,
      );

      await flow.callback();

      expect(failures[0]!.detail).toBe(
        'The identity provider refused the sign-in: access_denied: AADSTS50105: not assigned to a role',
      );
    });

    it("passes on the identity provider's refusal of the token request, such as a wrong client secret", async () => {
      const refusingTokens = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) =>
        String(input).endsWith('/token')
          ? Response.json(
              { error: 'invalid_client', error_description: 'AADSTS7000215: Invalid client secret provided.' },
              { status: 401 },
            )
          : fetchImpl(input, init)) as typeof fetch;
      const { handlers, failures } = reporting(refusingTokens);
      const flow = await startAndCallBack(handlers, (state) => `code=c&state=${state}`);

      await flow.callback();

      expect(failures[0]!.detail).toBe(
        'The identity provider refused the token request: invalid_client: AADSTS7000215: Invalid client secret provided.',
      );
    });

    it('names the unverified domain, not the tenant id', async () => {
      const { handlers, failures } = reporting();
      const flow = await startAndCallBack(handlers, (state) => `code=c&state=${state}`);
      await signIdToken({ sub: 'sub-bob', nonce: flow.login.nonce, email: 'bob@unverified.example' });

      await flow.callback();

      expect(failures[0]).toMatchObject({
        code: 'EMAIL_DOMAIN_NOT_VERIFIED',
        detail: "The identity provider signed in an address at unverified.example, an email domain that isn't verified",
      });
    });

    it('reports nothing when no auth domain can be named: a forged callback or an unknown auth domain', async () => {
      const { handlers, failures } = reporting();
      await handlers.oidcCallback(
        req('GET', 'https://app.test/auth/oidc/callback?code=c&state=s', { cookie: 'pn_session_oidc=forged.sig' }),
      );
      await handlers.oidcStart(req('GET', 'https://app.test/auth/oidc/start?authDomainId=999999'));

      expect(failures).toEqual([]);
    });

    it('still answers when the hook throws', async () => {
      const handlers = createAuthHandlers(
        makeConfig({
          signInErrorPath: '/sign-in',
          onSignInFailure: () => {
            throw new Error('database down');
          },
          oidc: oidcHandler({ fetch: fetchImpl, clientSecret: () => 'mock-secret' }),
        }),
      );
      const start = await handlers.oidcStart(
        req('GET', `https://app.test/auth/oidc/start?authDomainId=${authDomainId}`),
      );
      const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
      const stateCookie = setCookieValue(start, 'pn_session_oidc')!;

      const res = await handlers.oidcCallback(
        req('GET', `https://app.test/auth/oidc/callback?error=access_denied&state=${state}`, {
          cookie: `pn_session_oidc=${stateCookie}`,
        }),
      );

      expect(res.headers.get('location')).toBe('/sign-in?error=VERIFICATION_FAILED');
    });
  });

  describe('with sign-in hooks (#26)', () => {
    it("refuses a verified IdP user before a session exists, sending only the app's code to the error path", async () => {
      const before = await sessionCount();
      const config = makeConfig({
        signInErrorPath: '/sign-in/error',
        oidc: oidcHandler({ fetch: fetchImpl, clientSecret: () => 'mock-secret' }),
        signIn: {
          beforeSession: ({ method }) => {
            expect(method).toBe('oidc');
            throw new SignInRefusedError('No active workspace', 'NO_ACTIVE_WORKSPACE');
          },
        },
      });

      const res = await oidcSignIn(config, 'bob@globex.com');

      expect(res.status).toBe(302);
      expect(res.headers.get('location')).toBe('/sign-in/error?error=NO_ACTIVE_WORKSPACE');
      expect(setCookieValue(res, 'pn_session')).toBeFalsy();
      expect(await sessionCount()).toBe(before);
    });

    it('runs afterSignIn for an IdP sign-in', async () => {
      const seen: { user: ResolvedUser; method: SignInMethod }[] = [];
      const config = makeConfig({
        oidc: oidcHandler({ fetch: fetchImpl, clientSecret: () => 'mock-secret' }),
        signIn: { afterSignIn: ({ user, method }) => void seen.push({ user, method }) },
      });

      const res = await oidcSignIn(config, 'bob@globex.com');

      expect(res.status).toBe(302);
      expect(setCookieValue(res, 'pn_session')).toBeTruthy();
      expect(seen).toEqual([{ user: expect.objectContaining({ userId: db.ids.users.bob }), method: 'oidc' }]);
    });

    async function oidcSignIn(config: AuthHttpConfig, email: string): Promise<Response> {
      const handlers = createAuthHandlers(config);
      const start = await handlers.oidcStart(
        req('GET', `https://app.test/auth/oidc/start?authDomainId=${authDomainId}`),
      );
      const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
      const stateCookie = setCookieValue(start, 'pn_session_oidc')!;
      const login = await verifyLoginState(stateCookie, 'test-login-state-secret', 600);
      await signIdToken({ sub: `sub-${email}`, nonce: login!.nonce, email });
      return handlers.oidcCallback(
        req('GET', `https://app.test/auth/oidc/callback?code=test-code&state=${state}`, {
          cookie: `pn_session_oidc=${stateCookie}`,
        }),
      );
    }
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

async function sessionCount(): Promise<number> {
  const { rows } = await db.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM sessions');
  return rows[0]!.n;
}

const initiate = (identifier: string, slug?: string) =>
  req('POST', 'https://app.test/auth/otp/initiate', { slug, body: { identifier } });
const complete = (identifier: string, slug?: string) =>
  req('POST', 'https://app.test/auth/otp/complete', { slug, body: { identifier, credential: '123456' } });

describe('createAuthHandlers — code sign-in without a tenant (#26)', () => {
  it('serves code sign-in on the bare host, where the request names no tenant', async () => {
    const handlers = createAuthHandlers(makeConfig());

    expect((await handlers.otpInitiate(initiate('bob@globex.com'))).status).toBe(200);
    const done = await handlers.otpComplete(complete('bob@globex.com'));

    expect(done.status).toBe(200);
    expect(setCookieValue(done, 'pn_session')).toBeTruthy();
  });

  it('still answers 404 for a sub-domain that names no tenant', async () => {
    const handlers = createAuthHandlers(makeConfig());

    expect((await handlers.otpInitiate(initiate('bob@globex.com', 'nope'))).status).toBe(404);
    expect((await handlers.otpComplete(complete('bob@globex.com', 'nope'))).status).toBe(404);
  });
});

describe('createAuthHandlers — sign-in hooks (#26)', () => {
  it('beforeOtp replaces the identifier before it is used, at both steps', async () => {
    const steps: string[] = [];
    const handlers = createAuthHandlers(
      makeConfig({
        signIn: {
          beforeOtp: ({ identifier, kind, step }) => {
            steps.push(`${step}:${kind}`);
            return identifier.trim().toLowerCase();
          },
        },
      }),
    );

    expect((await handlers.otpInitiate(initiate('  BOB@globex.com '))).status).toBe(200);
    const done = await handlers.otpComplete(complete('  BOB@globex.com '));

    expect(done.status).toBe(200);
    expect(steps).toEqual(['initiate:email', 'complete:email']);
  });

  it("beforeOtp can refuse before anything is sent, with the app's message", async () => {
    let sent = 0;
    const handlers = createAuthHandlers(
      makeConfig({
        otpHandler: { ...mockOtp, initiate: async () => (sent++, { otpSent: true }) },
        signIn: {
          beforeOtp: ({ kind }) => {
            if (kind === 'phone') throw new SignInRefusedError('Text-message sign-in is switched off');
          },
        },
      }),
    );

    const res = await handlers.otpInitiate(initiate('+15555550100'));

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'Text-message sign-in is switched off', code: 'SIGN_IN_REFUSED' });
    expect(sent).toBe(0);
  });

  it("beforeSession refuses a verified user with the app's message, and no session is created", async () => {
    const before = await sessionCount();
    const handlers = createAuthHandlers(
      makeConfig({
        signIn: {
          beforeSession: ({ user, method }) => {
            expect(method).toBe('otp');
            if (user.userId === db.ids.users.bob) {
              throw new SignInRefusedError("You don't have access to an active workspace.", 'NO_ACTIVE_WORKSPACE');
            }
          },
        },
      }),
    );

    const res = await handlers.otpComplete(complete('bob@globex.com'));

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: "You don't have access to an active workspace.",
      code: 'NO_ACTIVE_WORKSPACE',
    });
    expect(setCookieValue(res, 'pn_session')).toBeFalsy();
    expect(await sessionCount()).toBe(before);
  });

  it('afterSignIn sees the signed-in user; if it throws, the error is logged and the sign-in stands', async () => {
    const seen: { user: ResolvedUser; method: SignInMethod }[] = [];
    const logged: string[] = [];
    const handlers = createAuthHandlers(
      makeConfig({
        logger: {
          debug() {},
          info() {},
          warn() {},
          error: (_data, msg) => void logged.push(msg),
        },
        signIn: {
          afterSignIn: ({ user, method }) => {
            seen.push({ user, method });
            throw new Error('login history is down');
          },
        },
      }),
    );

    const res = await handlers.otpComplete(complete('bob@globex.com'));

    expect(res.status).toBe(200);
    expect(setCookieValue(res, 'pn_session')).toBeTruthy();
    expect(seen).toEqual([{ user: expect.objectContaining({ userId: db.ids.users.bob }), method: 'otp' }]);
    expect(logged).toEqual(['afterSignIn hook failed; the sign-in stands']);
  });
});

describe('createAuthHandlers — one code handler per identifier kind (#26)', () => {
  it('sends each identifier to the handler for its kind', async () => {
    const used: string[] = [];
    const tagged = (tag: string): MethodHandler => ({
      initiate: async () => (used.push(tag), { otpSent: true }),
      complete: mockOtp.complete,
    });
    const handlers = createAuthHandlers(makeConfig({ otpHandler: { email: tagged('email'), phone: tagged('phone') } }));

    await handlers.otpInitiate(initiate('bob@globex.com'));
    await handlers.otpInitiate(initiate('+15555550100'));

    expect(used).toEqual(['email', 'phone']);
  });

  it('refuses a kind with no handler, and reports code sign-in as offered when any kind is', async () => {
    const handlers = createAuthHandlers(makeConfig({ otpHandler: { email: mockOtp } }));

    const res = await handlers.otpInitiate(initiate('+15555550100'));
    const options = await handlers.signInOptions(req('GET', 'https://app.test/auth/sign-in/options', { slug: 'acme' }));

    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: 'OTP_NOT_ALLOWED' });
    expect(((await options.json()) as OptionsBody).otpAllowed).toBe(true);
  });
});

describe('createAuthHandlers — otpInitiate when the send fails (#36)', () => {
  const failingEmail = () =>
    emailCodeHandler({
      codeSecret: 'test-email-code-secret-at-least-32-bytes',
      sendCode: async ({ to }) => {
        throw Object.assign(new Error(`Email address is not verified: ${to}`), { name: 'MessageRejected' });
      },
    });

  async function initiate(handlers: ReturnType<typeof createAuthHandlers>, identifier: string) {
    const res = await handlers.otpInitiate(req('POST', 'http://localhost/auth/otp/initiate', { body: { identifier } }));
    return { status: res.status, body: await res.text() };
  }

  it('answers a registered contact exactly as a stranger, and tells the logger without the address', async () => {
    const logged: string[] = [];
    const record = (data: Record<string, unknown>, msg: string) => void logged.push(JSON.stringify({ data, msg }));
    const handlers = createAuthHandlers(
      makeConfig({
        tenantSlugFromRequest: () => null,
        otpHandler: failingEmail(),
        logger: { debug: record, info: record, warn: record, error: record },
      }),
    );

    const known = await initiate(handlers, 'bob@globex.com');
    const stranger = await initiate(handlers, 'nobody-36@globex.com');

    expect(known).toEqual({ status: 200, body: JSON.stringify({ otpSent: true }) });
    expect(known).toEqual(stranger);
    expect(logged.join('\n')).toMatch(/MessageRejected/);
    expect(logged.join('\n')).not.toContain('bob@globex.com');
  });
});
