import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as jose from 'jose';
import { EmailDomainNotVerifiedError, InvalidInputError, VerificationFailedError } from '../src/index.js';
import { oidcHandler, type OidcParams, type OidcHandlerOptions } from '../src/methods/oidc/index.js';
import type { AuthDomain } from '../src/index.js';
import { seedVerifiedDomain } from './helpers/email-domains.js';
import { startTestDb, type TestDb } from './helpers/test-db.js';

// Unique issuer per case — the handler caches discovery per issuer at module
// scope, so reusing one across cases would cross-contaminate the mock.
let seq = 0;
const nextIssuer = () => `https://idp-${++seq}.example.test`;

/**
 * A minimal mock OIDC provider over `oauth4webapi`'s injected `fetch`: serves a
 * discovery doc, a JWKS, and a token endpoint returning a `jose`-signed
 * id_token. `signIdToken` is called after `initiate` (so the nonce matches).
 */
async function makeIdp(issuer: string, clientId: string) {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256');
  const jwk = { ...(await jose.exportJWK(publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' };
  const endpoints = {
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
  };
  let idToken = '';
  const signIdToken = async (claims: jose.JWTPayload) => {
    idToken = await new jose.SignJWT({ aud: clientId, iss: issuer, ...claims })
      .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
  };
  const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
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
  return { fetchImpl, signIdToken };
}

// A synthetic in-memory AuthDomain for testing the handler in isolation. The
// handler reads integrationParams, and complete() checks tenantId's verified
// email domains — so tests that reach complete() pass a seeded tenant.
// authDomainId is a placeholder: nothing reads it.
function authDomainFor(issuer: string, clientId = 'test-client', tenantId = 0): AuthDomain<OidcParams> {
  return {
    authDomainId: 0,
    tenantId,
    displayName: 'Test IdP',
    integrationType: 'oidc',
    integrationParams: { issuer, clientId, redirectUri: 'https://app.test/callback' },
  };
}

describe('oidcHandler.initiate', () => {
  it('discovers the provider and builds an authorization URL + login state', async () => {
    const issuer = nextIssuer();
    const { fetchImpl } = await makeIdp(issuer, 'test-client');
    const handler = oidcHandler({ fetch: fetchImpl });

    const { redirectUrl, loginState } = await handler.initiate(authDomainFor(issuer));
    const url = new URL(redirectUrl);

    expect(url.origin + url.pathname).toBe(`${issuer}/authorize`);
    expect(url.searchParams.get('client_id')).toBe('test-client');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('redirect_uri')).toBe('https://app.test/callback');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('state')).toBe(loginState.state);
    expect(url.searchParams.get('nonce')).toBe(loginState.nonce);
    expect(loginState.codeVerifier).toBeTruthy();
  });

  it('rejects a non-oidc auth_domain and incomplete params', async () => {
    const handler = oidcHandler();
    await expect(
      handler.initiate({ ...authDomainFor('https://x.test'), integrationType: 'saml' }),
    ).rejects.toBeInstanceOf(InvalidInputError);
    await expect(
      handler.initiate({
        authDomainId: 1,
        tenantId: 1,
        displayName: 'x',
        integrationType: 'oidc',
        integrationParams: { clientId: 'c', redirectUri: 'r' } as OidcParams,
      }),
    ).rejects.toBeInstanceOf(InvalidInputError);
  });
});

describe('oidcHandler.complete', () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await startTestDb();
    // acme's IdP may vouch for acme.com and nowhere.test — not for globex.com.
    await seedVerifiedDomain(db, db.ids.tenants.acme, 'acme.com');
    await seedVerifiedDomain(db, db.ids.tenants.acme, 'nowhere.test');
  });
  afterAll(async () => {
    await db.shutdown();
  });

  async function runFlow(opts: { email?: string; provisionUser?: OidcHandlerOptions['provisionUser'] }) {
    const issuer = nextIssuer();
    const idp = await makeIdp(issuer, 'test-client');
    const handler = oidcHandler({
      fetch: idp.fetchImpl,
      clientSecret: () => 'test-secret',
      provisionUser: opts.provisionUser,
    });
    const authDomain = authDomainFor(issuer, 'test-client', db.ids.tenants.acme);

    const { loginState } = await handler.initiate(authDomain);
    await idp.signIdToken({
      sub: 'entra-sub-1',
      nonce: loginState.nonce,
      ...(opts.email ? { email: opts.email } : {}),
    });
    const callbackUrl = `https://app.test/callback?code=test-code&state=${loginState.state}`;
    return handler.complete({ db: db.pool, authDomain, callbackUrl, loginState });
  }

  it('verifies the id_token and resolves the existing user', async () => {
    // alice@acme.com is a seeded communication method → resolves to Alice.
    const user = await runFlow({ email: 'alice@acme.com' });
    expect(user).toEqual({ userId: db.ids.users.alice, userCommunicationMethodId: db.ids.ucm.alice });
  });

  it('resolves the existing user when the IdP returns the email in a different casing', async () => {
    // Entra commonly returns mixed-case addresses.
    const user = await runFlow({ email: 'Alice@ACME.com' });
    expect(user).toEqual({ userId: db.ids.users.alice, userCommunicationMethodId: db.ids.ucm.alice });
  });

  it('throws VerificationFailedError when the id_token has no email/preferred_username', async () => {
    await expect(runFlow({})).rejects.toBeInstanceOf(VerificationFailedError);
  });

  it('throws VerificationFailedError for a verified identity with no user and no provisioning', async () => {
    await expect(runFlow({ email: 'ghost@nowhere.test' })).rejects.toBeInstanceOf(VerificationFailedError);
  });

  it('refuses an email at a domain the tenant has not verified, before lookup or provisioning', async () => {
    // bob@globex.com is a real, seeded user — but acme hasn't verified globex.com,
    // so acme's IdP can't sign him in, and the provisioning hook never runs.
    let provisioned = false;
    const err = await runFlow({
      email: 'bob@globex.com',
      provisionUser: async () => {
        provisioned = true;
        return { userId: db.ids.users.bob, userCommunicationMethodId: db.ids.ucm.bob };
      },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EmailDomainNotVerifiedError);
    expect(err).toMatchObject({ code: 'EMAIL_DOMAIN_NOT_VERIFIED', domain: 'globex.com' });
    expect(provisioned).toBe(false);
  });

  it('refuses a domain the tenant claimed but has not verified, and one another tenant verified', async () => {
    // Globex verified globex.com; acme merely claims it (verified_at NULL).
    await seedVerifiedDomain(db, db.ids.tenants.globex, 'globex.com');
    const c = await db.pool.connect();
    try {
      await c.query('BEGIN');
      await c.query(`SELECT set_config('app.actor_id', $1, true)`, [String(db.ids.appInit)]);
      await c.query(`INSERT INTO tenant_email_domains (tenant_id, domain) VALUES ($1, 'globex.com')`, [
        db.ids.tenants.acme,
      ]);
      await c.query('COMMIT');
    } finally {
      c.release();
    }
    await expect(runFlow({ email: 'bob@globex.com' })).rejects.toBeInstanceOf(EmailDomainNotVerifiedError);
  });

  it('provisions a new user via the provisionUser hook', async () => {
    // ghost@nowhere.test isn't seeded, so the hook stands in for provisioning a
    // fresh user. Its return flows straight back unchanged, so any seeded row
    // works as the stand-in — NoRoles fits "newly provisioned, no roles yet".
    const provisioned = { userId: db.ids.users.noRoles, userCommunicationMethodId: db.ids.ucm.noRoles };
    const user = await runFlow({ email: 'ghost@nowhere.test', provisionUser: async () => provisioned });
    expect(user).toEqual(provisioned);
  });
});
